#!/usr/bin/env python3
"""Build the Picblobs PoC with the real Mbed OS 5.15.9 build system."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from config_layout import AUTH_KEY_SIZE, CLIENT_CONFIG_SIZE, SERVER_CONFIG_SIZE

EXPECTED_MBED_VERSION = (5, 15, 9)
EXPECTED_MBED_COMMIT = "dfcb61e052d1192d99a07dca6fb4970281afc8e4"
VERSION_MACROS = (
    "MBED_MAJOR_VERSION",
    "MBED_MINOR_VERSION",
    "MBED_PATCH_VERSION",
)
ELF_MAGIC = b"\x7fELF"
MINIMUM_FIRMWARE_BYTES = 1024
GIT_DIRECTORY_PREFIX = "gitdir: "
GIT_REFERENCE_PREFIX = "ref: "
GIT_REFERENCE_ROOT = "refs"
GIT_OBJECT_ID_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compile the Picblobs PoC for NUCLEO_F429ZI with Mbed OS 5.15.9."
        )
    )
    parser.add_argument("--gcc", required=True)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--client-bin", required=True)
    parser.add_argument("--jobs", type=int, default=0)
    parser.add_argument(
        "--role",
        action="append",
        choices=("server", "client"),
        dest="roles",
        help="firmware role to build; repeat to build both (default: both)",
    )
    parser.add_argument("--source-root", default="modules/picblobs/mbed")
    parser.add_argument(
        "--mbed-os",
        help="optional Mbed OS source override for local SDK validation",
    )
    parser.add_argument(
        "--mbed-version-header",
        help="Bazel runfile used to locate the pinned Mbed OS source tree",
    )
    parser.add_argument(
        "--build-dir",
        default=".local/picblobs/mbed/NUCLEO_F429ZI/GCC_ARM",
    )
    args = parser.parse_args()

    workspace = Path(
        os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())
    ).resolve()
    source_root = resolve_workspace_path(workspace, args.source_root)
    mbed_os = resolve_mbed_os(
        workspace,
        source_override=args.mbed_os,
        version_header=args.mbed_version_header,
    )
    build_dir = resolve_workspace_path(workspace, args.build_dir)
    gcc = resolve_runfile(args.gcc)
    server_bin = resolve_runfile(args.server_bin)
    client_bin = resolve_runfile(args.client_bin)

    validate_project(source_root, server_bin, client_bin)
    validate_mbed_os(mbed_os)
    validate_compiler(gcc)
    validate_build_root(source_root, build_dir)
    validate_build_root(mbed_os, build_dir)

    previous_umask = os.umask(0o077)
    try:
        build_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        build_dir.chmod(0o700)
        roles = args.roles or ["server", "client"]
        for role in roles:
            result = build_role(
                source_root=source_root,
                mbed_os=mbed_os,
                build_root=build_dir,
                gcc=gcc,
                role=role,
                jobs=args.jobs,
            )
            if result:
                return result
    finally:
        os.umask(previous_umask)
    return 0


def build_role(
    *,
    source_root: Path,
    mbed_os: Path,
    build_root: Path,
    gcc: Path,
    role: str,
    jobs: int,
) -> int:
    with build_lock(build_root):
        return _build_role_locked(
            source_root=source_root,
            mbed_os=mbed_os,
            build_root=build_root,
            gcc=gcc,
            role=role,
            jobs=jobs,
        )


def _build_role_locked(
    *,
    source_root: Path,
    mbed_os: Path,
    build_root: Path,
    gcc: Path,
    role: str,
    jobs: int,
) -> int:
    role_build_dir = build_root / role
    role_config = build_root / f"mbed_app.{role}.json"
    write_role_config(source_root / "mbed_app.json", role_config, role)

    make_py = mbed_os / "tools" / "make.py"
    artifact_name = f"picblobs-mbed-poc-{role}"
    bootstrap = (
        "import collections, collections.abc, runpy, setuptools, sys; "
        "collections.MutableMapping = collections.abc.MutableMapping; "
        "sys.argv = [sys.argv[1], *sys.argv[2:]]; "
        "runpy.run_path(sys.argv[0], run_name='__main__')"
    )
    command = [
        sys.executable,
        "-c",
        bootstrap,
        str(make_py),
        "--mcu",
        "NUCLEO_F429ZI",
        "--tool",
        "GCC_ARM",
        "--source",
        str(source_root),
        "--source",
        str(mbed_os),
        "--build",
        str(role_build_dir),
        "--app-config",
        str(role_config),
        "--artifact-name",
        artifact_name,
        "--clean",
    ]
    if jobs:
        if jobs < 1:
            raise ValueError("jobs must be zero (automatic) or a positive integer")
        command.extend(["--jobs", str(jobs)])

    environment = os.environ.copy()
    environment["MBED_GCC_ARM_PATH"] = str(gcc.parent)
    environment["PYTHONPATH"] = os.pathsep.join(sys.path)

    print(
        f"compiling Picblobs {role} firmware with Mbed OS 5.15.9 "
        "for NUCLEO_F429ZI/GCC_ARM",
        flush=True,
    )
    result = subprocess.run(command, env=environment, check=False)
    if result.returncode != 0:
        return result.returncode

    firmware = role_build_dir / f"{artifact_name}.bin"
    executable = role_build_dir / f"{artifact_name}.elf"
    validate_artifact(firmware, "firmware", minimum_size=MINIMUM_FIRMWARE_BYTES)
    validate_artifact(executable, "ELF", magic=ELF_MAGIC)
    print_artifact(firmware)
    print_artifact(executable)
    return 0


@contextmanager
def build_lock(build_root: Path) -> Iterator[None]:
    build_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = build_root / ".compile.lock"
    with lock_path.open("a+b") as lock_file:
        lock_path.chmod(0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def validate_artifact(
    path: Path,
    kind: str,
    *,
    minimum_size: int = 1,
    magic: bytes | None = None,
) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Mbed build did not produce the expected {kind}: {path}")
    size = path.stat().st_size
    if size < minimum_size:
        raise ValueError(
            f"Mbed build produced an invalid {kind} ({size} bytes): {path}"
        )
    if magic is not None:
        with path.open("rb") as artifact:
            header = artifact.read(len(magic))
        if header != magic:
            raise ValueError(f"Mbed build produced an invalid {kind} header: {path}")


def write_role_config(source: Path, destination: Path, role: str) -> None:
    config = json.loads(source.read_text(encoding="utf-8"))
    try:
        config["config"]["blob_role"]["value"] = json.dumps(role)
    except (KeyError, TypeError) as error:
        raise ValueError("mbed_app.json does not define config.blob_role") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(config, indent=4, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def resolve_workspace_path(workspace: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = workspace / path
    return path.resolve()


def resolve_mbed_os(
    workspace: Path,
    *,
    source_override: str | None,
    version_header: str | None,
) -> Path:
    if source_override:
        return resolve_workspace_path(workspace, source_override)
    if not version_header:
        raise ValueError(
            "Mbed OS source is required; use the Bazel target or pass --mbed-os"
        )
    header = resolve_runfile(version_header)
    if header.name != "mbed_version.h" or header.parent.name != "platform":
        raise ValueError(f"invalid Mbed version header runfile: {header}")
    return header.parent.parent


def validate_build_root(source_root: Path, build_root: Path) -> None:
    if build_root == source_root or source_root in build_root.parents:
        raise ValueError(
            "Mbed build directory must be outside the project source tree"
        )


def resolve_runfile(value: str) -> Path:
    raw = Path(value)
    if raw.is_absolute() and raw.is_file():
        return raw
    for root_name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        root = os.environ.get(root_name)
        if not root:
            continue
        for prefix in ("", "_main", "hovel"):
            candidate = Path(root) / prefix / value
            if candidate.is_file():
                return candidate.resolve()
    candidate = Path.cwd() / value
    if candidate.is_file():
        return candidate.resolve()
    raise FileNotFoundError(f"missing runfile: {value}")


def validate_project(
    source_root: Path,
    server_bin: Path | None = None,
    client_bin: Path | None = None,
) -> None:
    required = (
        "main.cpp",
        "platform_mbed.cpp",
        "platform_mbed.h",
        "mbed_app.json",
        "blobs/nacl_client_blob.h",
        "blobs/nacl_server_blob.h",
    )
    missing = [name for name in required if not (source_root / name).is_file()]
    if missing:
        joined = ", ".join(missing)
        raise FileNotFoundError(
            f"Mbed project is missing {joined}; run task picblobs:mbed-blobs first"
        )
    validate_blob_configs(source_root, server_bin, client_bin)


def validate_blob_configs(
    source_root: Path,
    server_bin: Path | None = None,
    client_bin: Path | None = None,
) -> None:
    server = read_blob_header(source_root / "blobs" / "nacl_server_blob.h")
    client = read_blob_header(source_root / "blobs" / "nacl_client_blob.h")
    if len(server) < SERVER_CONFIG_SIZE or len(client) < CLIENT_CONFIG_SIZE:
        raise ValueError("generated Mbed blob headers are smaller than their configs")

    server_config = server[-SERVER_CONFIG_SIZE:]
    client_config = client[-CLIENT_CONFIG_SIZE:]
    server_key = server_config[-AUTH_KEY_SIZE:]
    client_key = client_config[-AUTH_KEY_SIZE:]
    if server_config[:2] != client_config[:2] or server_config[:2] == b"\0\0":
        raise ValueError("generated Mbed blobs must use the same nonzero port")
    if server_key != client_key or not any(server_key):
        raise ValueError("generated Mbed blobs must use the same nonzero auth key")
    if not any(client_config[2:6]):
        raise ValueError("generated Mbed client blob must use a nonzero server IPv4")
    validate_blob_code(server, server_bin, SERVER_CONFIG_SIZE, "server")
    validate_blob_code(client, client_bin, CLIENT_CONFIG_SIZE, "client")


def validate_blob_code(
    configured: bytes,
    binary_path: Path | None,
    config_size: int,
    role: str,
) -> None:
    if binary_path is None:
        return
    current = binary_path.read_bytes()
    if (
        len(configured) != len(current)
        or configured[:-config_size] != current[:-config_size]
    ):
        raise ValueError(
            f"generated Mbed {role} blob header is stale; "
            "run task picblobs:mbed-blobs"
        )


def read_blob_header(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    values = re.findall(r"\b0x([0-9a-fA-F]{2})\b", text)
    if not values:
        raise ValueError(f"generated Mbed blob header has no byte array: {path}")
    return bytes(int(value, 16) for value in values)


def validate_mbed_os(mbed_os: Path) -> None:
    make_py = mbed_os / "tools" / "make.py"
    version_header = mbed_os / "platform" / "mbed_version.h"
    if not make_py.is_file() or not version_header.is_file():
        raise FileNotFoundError(
            f"missing Mbed OS 5.15.9 source tree at {mbed_os}; "
            "use the Task-backed Bazel target or pass --mbed-os"
        )
    validate_checkout_commit(mbed_os)
    version_text = version_header.read_text(encoding="utf-8")
    found = tuple(read_version_macro(version_text, macro) for macro in VERSION_MACROS)
    if found != EXPECTED_MBED_VERSION:
        rendered = ".".join(str(part) for part in found)
        raise ValueError(
            f"Mbed OS checkout is {rendered}; expected exactly 5.15.9"
        )


def validate_checkout_commit(mbed_os: Path) -> None:
    """Validate a developer checkout when Git metadata is available.

    Bazel-managed source archives have no ``.git`` directory; their commit and
    digest are enforced by the repository rule before this program can run.
    """
    git_directory = resolve_git_directory(mbed_os)
    if git_directory is None:
        return
    commit = read_git_head(git_directory)
    if commit != EXPECTED_MBED_COMMIT:
        raise ValueError(
            f"Mbed OS checkout is commit {commit}; expected {EXPECTED_MBED_COMMIT}"
        )


def resolve_git_directory(work_tree: Path) -> Path | None:
    metadata = work_tree / ".git"
    if metadata.is_dir():
        return metadata.resolve()
    if not metadata.exists():
        return None
    if not metadata.is_file():
        raise ValueError(f"invalid Git metadata path: {metadata}")

    declaration = metadata.read_text(encoding="utf-8").strip()
    if not declaration.startswith(GIT_DIRECTORY_PREFIX):
        raise ValueError(f"invalid Git metadata file: {metadata}")
    value = declaration.removeprefix(GIT_DIRECTORY_PREFIX).strip()
    if not value:
        raise ValueError(f"Git metadata file has no directory: {metadata}")
    git_directory = Path(value)
    if not git_directory.is_absolute():
        git_directory = metadata.parent / git_directory
    git_directory = git_directory.resolve()
    if not git_directory.is_dir():
        raise FileNotFoundError(f"missing Git metadata directory: {git_directory}")
    return git_directory


def read_git_head(git_directory: Path) -> str:
    head_file = git_directory / "HEAD"
    if not head_file.is_file():
        raise FileNotFoundError(f"missing Git HEAD: {head_file}")
    head = head_file.read_text(encoding="ascii").strip()
    if GIT_OBJECT_ID_PATTERN.fullmatch(head):
        return head
    if not head.startswith(GIT_REFERENCE_PREFIX):
        raise ValueError(f"invalid Git HEAD: {head_file}")

    reference = head.removeprefix(GIT_REFERENCE_PREFIX).strip()
    reference_path = PurePosixPath(reference)
    if (
        not reference_path.parts
        or reference_path.parts[0] != GIT_REFERENCE_ROOT
        or any(part in ("", ".", "..") for part in reference_path.parts)
    ):
        raise ValueError(f"invalid Git HEAD reference: {reference}")

    common_directory = resolve_git_common_directory(git_directory)
    for root in (git_directory, common_directory):
        object_id = read_git_object_id(root.joinpath(*reference_path.parts))
        if object_id is not None:
            return object_id

    packed_references = common_directory / "packed-refs"
    if packed_references.is_file():
        for line in packed_references.read_text(encoding="ascii").splitlines():
            if not line or line.startswith(("#", "^")):
                continue
            fields = line.split(" ", maxsplit=1)
            if len(fields) == 2 and fields[1] == reference:
                object_id = fields[0]
                if GIT_OBJECT_ID_PATTERN.fullmatch(object_id):
                    return object_id
                raise ValueError(f"invalid packed Git object ID for {reference}")
    raise ValueError(f"Git HEAD reference does not resolve: {reference}")


def resolve_git_common_directory(git_directory: Path) -> Path:
    declaration = git_directory / "commondir"
    if not declaration.is_file():
        return git_directory
    value = declaration.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"Git common directory file is empty: {declaration}")
    common_directory = Path(value)
    if not common_directory.is_absolute():
        common_directory = git_directory / common_directory
    common_directory = common_directory.resolve()
    if not common_directory.is_dir():
        raise FileNotFoundError(
            f"missing Git common metadata directory: {common_directory}"
        )
    return common_directory


def read_git_object_id(path: Path) -> str | None:
    if not path.is_file():
        return None
    object_id = path.read_text(encoding="ascii").strip()
    if not GIT_OBJECT_ID_PATTERN.fullmatch(object_id):
        raise ValueError(f"invalid Git object ID: {path}")
    return object_id


def read_version_macro(text: str, macro: str) -> int:
    match = re.search(rf"^#define\s+{macro}\s+(\d+)\s*$", text, re.MULTILINE)
    if not match:
        raise ValueError(f"Mbed version header does not define {macro}")
    return int(match.group(1))


def validate_compiler(gcc: Path) -> None:
    if gcc.name != "arm-none-eabi-gcc" or not os.access(gcc, os.X_OK):
        raise ValueError(f"invalid Arm GCC executable: {gcc}")
    result = subprocess.run(
        [str(gcc), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", result.stdout)
    if not match or int(match.group(1)) != 9:
        version = match.group(0) if match else "unknown"
        raise ValueError(
            f"Arm GCC is {version}; Mbed OS 5.15.9 requires a 9.x compiler"
        )


def print_artifact(path: Path) -> None:
    contents = path.read_bytes()
    digest = hashlib.sha256(contents).hexdigest()
    print(f"built {path}: {len(contents)} bytes, sha256={digest}")


if __name__ == "__main__":
    raise SystemExit(main())

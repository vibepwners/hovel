#!/usr/bin/env python3
"""Validate, smoke-test, and inventory Hovel release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
import venv
from pathlib import Path

import click

VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$")
PUBLISH_TRUE = frozenset({"1", "true", "yes"})


def repository_root() -> Path:
    return Path(os.environ.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd())).resolve()


def project_version(path: Path) -> str:
    return str(tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"])


def captured(pattern: str, path: Path) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise ValueError(f"could not find version in {path}")
    return match.group(1)


def version_inventory(root: Path) -> dict[str, str]:
    picblobs = root / "modules/picblobs"
    return {
        "hovel": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "core": (root / "core/VERSION").read_text(encoding="utf-8").strip(),
        "hovel-sdk": project_version(root / "sdk/python/pyproject.toml"),
        "agent": str(json.loads((root / "agent/.claude-plugin/plugin.json").read_text(encoding="utf-8"))["version"]),
        "picblobs": project_version(picblobs / "python/pyproject.toml"),
        "picblobs-cli": project_version(picblobs / "python_cli/pyproject.toml"),
        "picblobs-module": captured(r"^\s+version: ([^ \n]+)$", picblobs / "hovel-module.yaml"),
        "picblobs-provider": captured(r'^const providerVersion = "([^"]+)"$', picblobs / "provider/provider.go"),
        "picblobs-runtime": captured(r'^__version__ = "([^"]+)"$', picblobs / "python/picblobs/__init__.py"),
    }


def component_changed(root: Path, path: str, current_tag: str) -> bool:
    result = subprocess.run(
        ["git", "tag", "--merged", "HEAD", "--sort=-version:refname", "--list", "v[0-9]*"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    previous = next((tag for tag in result.stdout.splitlines() if tag != current_tag), "")
    if not previous:
        return True
    changed = subprocess.run(
        ["git", "diff", "--quiet", f"{previous}..HEAD", "--", path],
        cwd=root,
        check=False,
    )
    if changed.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(changed.returncode, changed.args)
    return changed.returncode == 1


def validate(root: Path, tag: str, publish: bool, require_main: bool) -> None:
    versions = version_inventory(root)
    hovel = versions["hovel"]
    for name in ("core", "hovel-sdk", "agent"):
        if versions[name] != hovel:
            raise ValueError(f"{name} version {versions[name]!r} does not match Hovel {hovel!r}")
    pic = versions["picblobs"]
    for name in ("picblobs-cli", "picblobs-module", "picblobs-provider", "picblobs-runtime"):
        if versions[name] != pic:
            raise ValueError(f"{name} version {versions[name]!r} does not match Picblobs {pic!r}")
    dependency = tomllib.loads((root / "modules/picblobs/python_cli/pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    if f"picblobs>={pic}" not in dependency:
        raise ValueError(f"picblobs-cli must require picblobs>={pic}")
    if publish and not tag:
        raise ValueError("publishing requires an explicit tag")
    if tag:
        match = VERSION_RE.fullmatch(tag)
        if match is None or match.group(1) != hovel:
            raise ValueError(f"release tag {tag!r} does not match Hovel {hovel!r}")
    if require_main:
        subprocess.run(["git", "fetch", "--quiet", "origin", "main"], cwd=root, check=True)
        result = subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], cwd=root, check=False)
        if result.returncode != 0:
            raise ValueError("release commit is not contained in origin/main")
    print(json.dumps(versions, indent=2, sort_keys=True))
    picblobs_changed = component_changed(root, "modules/picblobs", tag)
    print(f"picblobs changed since the previous Hovel tag: {str(picblobs_changed).lower()}")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as output:
            output.write(f"hovel_version={hovel}\n")
            output.write(f"picblobs_version={pic}\n")
            output.write(f"picblobs_changed={str(picblobs_changed).lower()}\n")
            source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            output.write(f"source_sha={source_sha}\n")


def artifact_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and path.name not in {"SHA256SUMS", "release-manifest.json"})


def write_manifest(root: Path, tag: str, output: Path, checksums: Path, repo: Path) -> None:
    files = artifact_files(root)
    artifacts = []
    lines = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(root).as_posix()
        artifacts.append({"path": relative, "sha256": digest, "size": path.stat().st_size})
        lines.append(f"{digest}  {relative}")
    payload = {"schemaVersion": 1, "tag": tag, "components": version_inventory(repo), "artifacts": artifacts}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksums.write_text("\n".join(lines) + "\n", encoding="utf-8")


def stage_assets(sources: list[Path], output: Path) -> None:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    for source in sources:
        for path in artifact_files(source):
            destination = output / path.name
            if destination.exists():
                raise ValueError(f"duplicate release asset name: {path.name}")
            shutil.copy2(path, destination)


def one_wheel(dist: Path, prefix: str, platform: str = "") -> Path:
    wheels = sorted(path for path in dist.glob("*.whl") if path.name.startswith(prefix) and platform in path.name)
    if len(wheels) != 1:
        raise ValueError(f"expected one {prefix} wheel containing {platform!r}, got {wheels}")
    return wheels[0]


def smoke(package: str, dist: Path, dependency_dist: Path | None) -> None:
    versions = version_inventory(repository_root())
    version = versions[package]
    with tempfile.TemporaryDirectory(prefix="hovel-release-smoke-") as temporary:
        environment = Path(temporary) / "venv"
        venv.EnvBuilder(with_pip=True, clear=True, system_site_packages=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        bindir = python.parent
        smoke_environment = os.environ.copy()
        click_import_root = str(Path(click.__file__).resolve().parent.parent)
        smoke_environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (click_import_root, smoke_environment.get("PYTHONPATH", "")) if part
        )
        wheels = []
        if dependency_dist is not None:
            wheels.append(one_wheel(dependency_dist, f"picblobs-{versions['picblobs']}-"))
        if package == "hovel":
            wheels.append(one_wheel(dist, f"hovel-{version}-", "manylinux_2_28_x86_64"))
        else:
            wheels.append(one_wheel(dist, f"{package.replace('-', '_')}-{version}-"))
        subprocess.run(
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps", *map(str, wheels)],
            check=True,
        )
        if package == "hovel":
            subprocess.run([str(bindir / "hovel"), "version"], check=True)
        elif package == "hovel-sdk":
            subprocess.run([str(python), "-c", "import hovel_sdk"], check=True)
        elif package == "picblobs":
            subprocess.run([str(python), "-c", "import picblobs; assert picblobs.list_blobs()"], check=True)
        else:
            subprocess.run(
                [str(bindir / "picblobs-cli"), "--help"],
                check=True,
                env=smoke_environment,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                [str(python), "-c", "import picblobs, picblobs_cli; assert picblobs.list_blobs()"],
                check=True,
                env=smoke_environment,
            )


def verify_pypi(package: str, version: str, dist: Path) -> None:
    expected = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(dist.iterdir())
        if path.is_file() and path.suffix in {".whl", ".gz"}
    }
    if not expected:
        raise ValueError(f"no distributions found in {dist}")
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    actual: dict[str, str] = {}
    for attempt in range(6):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                payload = json.load(response)
            actual = {item["filename"]: item["digests"]["sha256"] for item in payload["urls"]}
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        if actual == expected:
            print(f"verified {package} {version} on PyPI ({len(actual)} files)")
            return
        if attempt < 5:
            time.sleep(5)
    raise ValueError(f"PyPI artifact mismatch for {package} {version}: expected {expected}, got {actual}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate_parser = commands.add_parser("validate")
    validate_parser.add_argument("--tag", default="")
    validate_parser.add_argument("--publish", default="false")
    validate_parser.add_argument("--require-main", action="store_true")
    manifest_parser = commands.add_parser("manifest")
    manifest_parser.add_argument("--tag", required=True)
    manifest_parser.add_argument("--root", type=Path, required=True)
    manifest_parser.add_argument("--output", type=Path, required=True)
    manifest_parser.add_argument("--checksums", type=Path, required=True)
    stage_parser = commands.add_parser("stage-assets")
    stage_parser.add_argument("--source", action="append", type=Path, required=True)
    stage_parser.add_argument("--output", type=Path, required=True)
    smoke_parser = commands.add_parser("smoke")
    smoke_parser.add_argument("--package", choices=("hovel", "hovel-sdk", "picblobs", "picblobs-cli"), required=True)
    smoke_parser.add_argument("--dist", type=Path, required=True)
    smoke_parser.add_argument("--dependency-dist", type=Path)
    pypi_parser = commands.add_parser("verify-pypi")
    pypi_parser.add_argument("--package", required=True)
    pypi_parser.add_argument("--version", required=True)
    pypi_parser.add_argument("--dist", type=Path, required=True)
    args = parser.parse_args(argv)
    repo = repository_root()
    try:
        if args.command == "validate":
            validate(repo, args.tag, args.publish.lower() in PUBLISH_TRUE, args.require_main)
        elif args.command == "manifest":
            write_manifest((repo / args.root).resolve(), args.tag, (repo / args.output).resolve(), (repo / args.checksums).resolve(), repo)
        elif args.command == "stage-assets":
            stage_assets([(repo / source).resolve() for source in args.source], (repo / args.output).resolve())
        elif args.command == "smoke":
            smoke(args.package, (repo / args.dist).resolve(), (repo / args.dependency_dist).resolve() if args.dependency_dist else None)
        else:
            verify_pypi(args.package, args.version, (repo / args.dist).resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"release error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

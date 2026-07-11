"""Update repository Python locks with the Bazel-managed uv binary."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

PYTHON_VERSION = "3.12"
DEFAULT_LOCK_MODE = 0o644


@dataclass(frozen=True)
class ProjectLock:
    directory: Path
    export: Path | None = None
    extra: str | None = None


@dataclass(frozen=True)
class RequirementsLock:
    source: Path
    output: Path


def _workspace() -> Path:
    value = os.environ.get("BUILD_WORKSPACE_DIRECTORY")
    if not value:
        raise RuntimeError("update_python_locks must run through `task python:deps`")
    return Path(value).resolve()


def _run(command: list[str], *, cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)  # noqa: S603


def _copy_project(project: ProjectLock, scratch: Path) -> ProjectLock:
    destination = scratch / project.directory.name
    destination.mkdir(parents=True)
    for name in ("pyproject.toml", "uv.lock"):
        source = project.directory / name
        if source.exists():
            shutil.copy2(source, destination / name)
    export = destination / project.export.name if project.export is not None else None
    return ProjectLock(directory=destination, export=export, extra=project.extra)


def _update_project(uv: Path, project: ProjectLock) -> None:
    _run([str(uv), "lock", "--upgrade", "--no-progress", "--quiet"], cwd=project.directory)
    if project.export is None:
        return
    command = [
        str(uv),
        "export",
        "--frozen",
        "--format=requirements.txt",
        "--no-annotate",
        "--no-emit-project",
        "--no-header",
        "--no-progress",
        "--quiet",
        f"--output-file={project.export}",
    ]
    if project.extra is not None:
        command.extend(("--extra", project.extra))
    _run(command, cwd=project.directory)


def _compile_requirements(uv: Path, lock: RequirementsLock, scratch: Path) -> Path:
    scratch.mkdir(parents=True)
    output = scratch / lock.output.name
    command = [
        str(uv),
        "pip",
        "compile",
        str(lock.source),
        "--generate-hashes",
        "--no-annotate",
        "--no-header",
        "--no-progress",
        "--quiet",
        f"--python-version={PYTHON_VERSION}",
        "--upgrade",
        f"--output-file={output}",
    ]
    _run(command, cwd=lock.source.parent)
    return output


def _replace_if_changed(source: Path, destination: Path) -> None:
    content = source.read_bytes()
    if destination.exists() and destination.read_bytes() == content:
        return
    mode = stat.S_IMODE(destination.stat().st_mode) if destination.exists() else DEFAULT_LOCK_MODE
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        temporary.chmod(mode)
        temporary.replace(destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def update_python_locks(uv: Path, workspace: Path) -> None:
    projects = (
        ProjectLock(workspace / "sdk/python"),
        ProjectLock(
            workspace / "modules/picblobs/python",
            export=workspace / "modules/picblobs/python/requirements.txt",
            extra="dev",
        ),
    )
    requirements = (
        RequirementsLock(
            workspace / "core/tools/lint/requirements.in",
            workspace / "core/tools/lint/requirements_lock.txt",
        ),
        RequirementsLock(
            workspace / "modules/picblobs/mbed/requirements.in",
            workspace / "modules/picblobs/mbed/requirements.txt",
        ),
    )
    with tempfile.TemporaryDirectory(prefix="hovel-python-locks-") as temporary:
        scratch = Path(temporary)
        staged_projects: list[tuple[ProjectLock, ProjectLock]] = []
        for index, project in enumerate(projects):
            staged = _copy_project(project, scratch / str(index))
            _update_project(uv, staged)
            staged_projects.append((project, staged))
        staged_requirements = [
            (lock, _compile_requirements(uv, lock, scratch / f"requirements-{index}"))
            for index, lock in enumerate(requirements)
        ]

        for original, staged in staged_projects:
            _replace_if_changed(staged.directory / "uv.lock", original.directory / "uv.lock")
            if original.export is not None and staged.export is not None:
                _replace_if_changed(staged.export, original.export)
        for lock, staged in staged_requirements:
            _replace_if_changed(staged, lock.output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uv", type=Path, required=True)
    args = parser.parse_args()
    update_python_locks(args.uv.resolve(), _workspace())


if __name__ == "__main__":
    main()

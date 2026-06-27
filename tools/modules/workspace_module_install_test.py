#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


MODULES = (
    ("etro-survey", "survey", "python", "etro_survey", "hovel_etro_survey"),
    ("etro-exploit", "exploit", "python", "etro_exploit", "hovel_etro_exploit"),
    ("mock-survey", "survey", "python", "mock_survey", "hovel_example_survey"),
    ("mock-exploit", "exploit", "python", "mock_exploit", "hovel_example_exploit"),
    ("mock-exploit-session", "exploit", "python", "mock_exploit_session", "hovel_example_exploit_session"),
    ("mock-survey-go", "survey", "command", "0", ""),
    ("mock-exploit-go", "exploit", "command", "1", ""),
    ("mock-exploit-session-go", "exploit", "command", "2", ""),
    ("mock-survey-rust", "survey", "command", "3", ""),
    ("mock-exploit-rust", "exploit", "command", "4", ""),
    ("mock-exploit-session-rust", "exploit", "command", "5", ""),
    ("squatter", "payload_provider", "command", "6", ""),
)


def main() -> int:
    if len(os.sys.argv) != 9:
        raise SystemExit("usage: workspace_module_install_test.py <hovel> <seven module binaries>")
    hovel_bin = resolve_path(os.sys.argv[1])
    binaries = [resolve_path(arg) for arg in os.sys.argv[2:]]
    python_root = find_runfile("examples/python")
    sdk_root = find_runfile("sdk/python")

    with tempfile.TemporaryDirectory(prefix="hovel-workspace-module-install-", dir=test_tmpdir()) as tmp_raw:
        tmp = Path(tmp_raw)
        workspace = tmp / "workspace"
        packages = tmp / "packages"
        packages.mkdir()
        empty_config = tmp / "empty-modules.json"
        empty_config.write_text('{"modules":[]}\n')
        env = os.environ | {
            "HOVEL_MODULE_CONFIG": str(empty_config),
            "HOVEL_PYTHON_SDK_ROOT": str(sdk_root),
        }

        run([str(hovel_bin), "init", "--workspace", str(workspace), "--json"], env=env)
        for name, module_type, kind, value, module in MODULES:
            if kind == "python":
                write_python_package(packages, name, module_type, python_root / value, module, sdk_root)
            else:
                write_command_package(packages, name, module_type, binaries[int(value)])

        for package_root in sorted(packages.iterdir()):
            run([str(hovel_bin), "module", "install", "--link", str(package_root), "--workspace", str(workspace)], env=env)

        lock = workspace / "module-lock.yaml"
        if not lock.exists():
            raise AssertionError("module lock was not written")
        lock_count = sum(1 for line in lock.read_text().splitlines() if line.strip().startswith("- name:"))
        if lock_count != 12:
            raise AssertionError(f"module lock contains {lock_count} modules, want 12\n{lock.read_text()}")

        list_out = run([str(hovel_bin), "module", "list", "--workspace", str(workspace)], env=env)
        for name, *_ in MODULES:
            require_contains(list_out, f"{name}@0.1.0")

        check_out = run([str(hovel_bin), "module", "check", "--all", "--workspace", str(workspace)], env=env)
        require_contains(check_out, "MODULE CHECKS")
        require_contains(check_out, "12 passed")
    return 0


def write_command_package(packages: Path, name: str, module_type: str, binary: Path) -> None:
    root = packages / name
    (root / "bin").mkdir(parents=True)
    write_manifest(root, name, module_type)
    target = root / "bin" / name
    shutil.copy2(binary, target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_python_package(packages: Path, name: str, module_type: str, project_dir: Path, module: str, sdk_root: Path) -> None:
    root = packages / name
    (root / "bin").mkdir(parents=True)
    write_manifest(root, name, module_type)
    launcher = root / "bin" / name
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "from __future__ import annotations\n"
        "import os\n"
        "import runpy\n"
        "import sys\n"
        f"sys.path[:0] = [{str(sdk_root)!r}, {str(project_dir)!r}]\n"
        f"runpy.run_module({module!r}, run_name='__main__')\n"
    )
    launcher.chmod(0o755)


def write_manifest(root: Path, name: str, module_type: str) -> None:
    (root / "hovel-module.yaml").write_text(
        f"""apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: {name}
  version: 0.1.0
  moduleType: {module_type}
  summary: In-tree functional test package for {name}
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/{name}"]
"""
    )


def run(argv: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(argv, check=True, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    return result.stdout


def require_contains(text: str, expected: str) -> None:
    if expected not in text:
        raise AssertionError(f"expected output to include {expected!r}:\n{text}")


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate.resolve()
    return find_runfile(path)


def find_runfile(rel: str) -> Path:
    for root in runfile_roots():
        for prefix in ("", "_main", "hovel"):
            candidate = root / prefix / rel
            if candidate.exists():
                return candidate.resolve()
    raise SystemExit(f"missing runfile: {rel}")


def runfile_roots() -> list[Path]:
    roots = [Path.cwd()]
    for name in ("RUNFILES_DIR", "TEST_SRCDIR"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    return roots


def test_tmpdir() -> str | None:
    return "/tmp"


if __name__ == "__main__":
    raise SystemExit(main())

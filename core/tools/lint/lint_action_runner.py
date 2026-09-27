"""Run a linter against a declared, writable source snapshot with isolated caches."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def run(spec: dict, output: Path, execroot: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hovel-lint-") as scratch:
        work = Path(scratch)
        source = work / "source"
        source.mkdir()
        for name, path in spec["sources"].items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("lint source escapes snapshot")
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(execroot / path, destination)
        cache = work / "cache"
        cache.mkdir()
        env = {
            "HOME": str(work), "TMPDIR": str(cache), "TEST_TMPDIR": str(cache),
            "BUILD_WORKSPACE_DIRECTORY": str(source / spec["cwd"]),
            "HOVEL_REPO_ROOT": str(source), "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOENV": "off",
            "GOFLAGS": "-mod=readonly", "GOCACHE": str(cache / "go-build"),
            "GOMODCACHE": str(cache / "go-mod"), "GOPATH": str(cache / "go"),
            "GOLANGCI_LINT_CACHE": str(cache / "golangci"), "XDG_CACHE_HOME": str(cache),
            # rules_python's generated bootstrap uses the execution image's
            # POSIX utilities. Linter binaries themselves are explicit inputs.
            "PATH": "/usr/bin:/bin",
        }
        if spec.get("go"):
            go = execroot / spec["go"]
            env["PATH"] = str(go.parent) + os.pathsep + env["PATH"]
            env["GOROOT"] = str(go.parent.parent)
        for path in spec.get("module_cache", []):
            relative = path.split("/cache/download/", 1)[1]
            destination = cache / "go-mod/cache/download" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(execroot / path, destination)
        executable = execroot / spec["executable"]
        args = [arg.replace("@EXECROOT@", str(execroot)) for arg in spec["arguments"]]
        started = time.monotonic()
        result = subprocess.run([str(executable), *args], cwd=source / spec["cwd"], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        log = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.stdout)
        log = log.replace(str(source), "<source>").replace(str(work), "<scratch>").replace(str(execroot), "<execroot>")
        (output / "diagnostics.log").write_text(log)
        (output / "result.json").write_text(json.dumps({
            "schema_version": "hovel.lint-action/v1", "id": spec["id"],
            "status": "PASSED" if result.returncode == 0 else "FAILED", "exit_code": result.returncode,
            "duration": round(time.monotonic() - started, 3),
        }, sort_keys=True) + "\n")


if __name__ == "__main__":
    run(json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]).absolute(), Path.cwd())

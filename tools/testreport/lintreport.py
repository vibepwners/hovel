from __future__ import annotations

import io
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import tokenize
from pathlib import Path
from typing import Any, TextIO


SCHEMA_VERSION = "hovel.lint-report/v1"
MANIFEST_VERSION = "hovel.lint-tools/v1"
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".ruff_cache",
    ".sl",
    ".task",
    ".test-report",
    ".venv",
    "__pycache__",
    "_site",
    "build",
    "dist",
    "node_modules",
    "target",
    "tmp",
}
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def run_manifest(repo: Path, manifest_path: Path, output: Path, *, selected: set[str] | None = None) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_manifest(manifest)
    if output.exists():
        shutil.rmtree(output)
    logs = output / "logs"
    logs.mkdir(parents=True)

    results: list[dict[str, Any]] = []
    overall = 0
    for tool in manifest["tools"]:
        if selected and tool["id"] not in selected:
            continue
        result = run_tool(repo, tool, logs)
        results.append(result)
        if result["status"] != "PASSED":
            overall = 1

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tools": results,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return overall


def validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_VERSION:
        raise ValueError(f"lint tool manifest must use {MANIFEST_VERSION}")
    tools = manifest.get("tools")
    if not isinstance(tools, list) or not tools:
        raise ValueError("lint tool manifest must contain tools")
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError("lint tool entries must be objects")
        tool_id = tool.get("id")
        if not isinstance(tool_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", tool_id):
            raise ValueError(f"invalid lint tool id: {tool_id!r}")
        if tool_id in seen:
            raise ValueError(f"duplicate lint tool id: {tool_id}")
        seen.add(tool_id)
        if tool.get("kind") not in {"formatter", "linter", "static-analysis"}:
            raise ValueError(f"invalid kind for {tool_id}")
        commands = tool.get("commands")
        if not isinstance(commands, list) or not commands or any(
            not isinstance(command, list) or not command or not all(isinstance(arg, str) and arg for arg in command)
            for command in commands
        ):
            raise ValueError(f"invalid commands for {tool_id}")


def run_tool(repo: Path, tool: dict[str, Any], logs: Path) -> dict[str, Any]:
    started = time.monotonic()
    log_path = logs / f"{tool['id']}.log"
    exit_codes: list[int] = []
    commands = tool["commands"]
    with log_path.open("w", encoding="utf-8") as log:
        for command in commands:
            display = shlex.join(command)
            write_line(log, f"$ {display}")
            exit_code = stream_command(repo, command, log)
            exit_codes.append(exit_code)
            write_line(log, f"[exit code: {exit_code}]\n")
    duration = round(time.monotonic() - started, 3)
    ignores = find_ignore_statements(repo, tool.get("ignore", {}))
    relative_log = relative_or_absolute(repo, log_path)
    status = "PASSED" if all(code == 0 for code in exit_codes) else "FAILED"
    print(f"{status:6} {tool['name']} ({duration:.2f}s, {len(ignores)} source ignores)", flush=True)
    return {
        "id": tool["id"],
        "name": tool["name"],
        "kind": tool["kind"],
        "scope": tool["scope"],
        "status": status,
        "duration": duration,
        "commands": [shlex.join(command) for command in commands],
        "ignore_statements": ignores,
        "raw_log_path": relative_log,
    }


def stream_command(repo: Path, command: list[str], log: TextIO) -> int:
    try:
        process = subprocess.Popen(
            command,
            cwd=repo,
            env=os.environ.copy() | {"PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except OSError as error:
        write_line(log, f"unable to start command: {error}")
        return 127
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        log.write(ANSI_ESCAPE.sub("", line).replace("\r", ""))
        log.flush()
    return process.wait()


def write_line(log: TextIO, line: str) -> None:
    print(line, flush=True)
    log.write(line + "\n")
    log.flush()


def find_ignore_statements(repo: Path, config: Any) -> list[dict[str, Any]]:
    if not isinstance(config, dict):
        return []
    pattern = config.get("pattern", "")
    if not isinstance(pattern, str) or not pattern:
        return []
    regex = re.compile(pattern)
    extensions = set(config.get("extensions", []))
    names = set(config.get("names", []))
    statements: list[dict[str, Any]] = []
    for path in source_files(repo, extensions=extensions, names=names):
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in candidate_ignore_lines(path, text):
            for _match in regex.finditer(line):
                statements.append(
                    {
                        "path": path.relative_to(repo).as_posix(),
                        "line": line_number,
                        "text": line.strip()[:240],
                    }
                )
    return statements


def candidate_ignore_lines(path: Path, text: str) -> list[tuple[int, str]]:
    """Return source lines that can contain directives, excluding Python strings."""
    lines = text.splitlines()
    if path.suffix not in {".py", ".pyi"}:
        return list(enumerate(lines, 1))

    comments: list[tuple[int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                comments.append((token.start[0], lines[token.start[0] - 1]))
    except (IndentationError, tokenize.TokenError):
        return []
    return comments


def source_files(repo: Path, *, extensions: set[str], names: set[str]) -> list[Path]:
    files: list[Path] = []
    for directory, child_dirs, filenames in os.walk(repo):
        root = Path(directory)
        child_dirs[:] = [name for name in child_dirs if not excluded(repo, root / name)]
        if excluded(repo, root):
            continue
        for filename in filenames:
            path = root / filename
            if filename in names or path.suffix in extensions:
                files.append(path)
    return sorted(files)


def excluded(repo: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(repo)
    except ValueError:
        return True
    return any(part in EXCLUDED_PARTS or part.startswith("bazel-") for part in relative.parts)


def relative_or_absolute(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()

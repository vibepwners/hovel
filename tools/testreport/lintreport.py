from __future__ import annotations

import io
import json
import os
import re
import shlex
import shutil
import time
import tokenize
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "hovel.lint-report/v1"
MANIFEST_VERSION = "hovel.lint-tools/v1"
COMPONENTS = {
    "gofmt": ["gofmt-core", "gofmt-modules"],
    "ruff": ["ruff-sdk", "ruff-picblobs"],
    "mypy": ["mypy-sdk"],
    "pydoclint": ["pydoclint-sdk"],
    "clang-format": ["clang-format-squatter", "clang-format-picblobs"],
    "clang-tidy": ["clang-tidy-squatter", "clang-tidy-picblobs"],
    "cppcheck": ["cppcheck-squatter", "cppcheck-picblobs"],
    "lizard": ["lizard-squatter", "lizard-picblobs"],
}
NATIVE_COMPONENTS = {
    "nilness", "clang-format-squatter", "clang-tidy-squatter", "clang-tidy-picblobs",
    "cppcheck-squatter", "cppcheck-picblobs", "lizard-squatter",
}
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


def materialize_results(repo: Path, manifest_path: Path, output: Path, directories: list[Path], *,
                        verified_native: set[str] | None = None, selected: set[str] | None = None) -> int:
    manifest = json.loads(manifest_path.read_text())
    validate_manifest(manifest)
    native = verified_native or set()
    if native - NATIVE_COMPONENTS:
        raise ValueError("unknown native lint verification")
    records = {}
    for directory in directories:
        record = json.loads((directory / "result.json").read_text())
        if record.get("schema_version") != "hovel.lint-action/v1" or record.get("status") not in {"PASSED", "FAILED"}:
            raise ValueError("invalid lint action result")
        if record["id"] in records:
            raise ValueError("duplicate lint action result")
        records[record["id"]] = (record, (directory / "diagnostics.log").read_text())
    if output.exists():
        shutil.rmtree(output)
    logs = output / "logs"
    logs.mkdir(parents=True)
    results = []
    for tool in manifest["tools"]:
        if selected and tool["id"] not in selected:
            continue
        passed = True
        duration = 0.0
        messages = ["Consumed declared lint results. Durations are from their producing actions, not this CI invocation.\n"]
        for component in COMPONENTS.get(tool["id"], [tool["id"]]):
            if component in records:
                record, diagnostic = records[component]
                passed &= record["status"] == "PASSED"
                duration += record.get("duration", 0.0)
                messages.append(f"{component}: {record['status']} (exit {record['exit_code']})\n{diagnostic}\n")
            elif component in native:
                messages.append(f"{component}: PASSED by the preceding Aspect native check; timing and diagnostics are in its build events.\n")
            else:
                passed = False
                messages.append(f"{component}: MISSING evidence; run aspect hovel-report.\n")
        log = logs / (tool["id"] + ".log")
        log.write_text(ANSI_ESCAPE.sub("", "".join(messages)).replace("\r", ""))
        results.append({
            "id": tool["id"], "name": tool["name"], "kind": tool["kind"], "scope": tool["scope"],
            "status": "PASSED" if passed else "FAILED", "duration": round(duration, 3),
            "commands": [shlex.join(command) for command in tool["commands"]],
            "ignore_statements": find_ignore_statements(repo, tool.get("ignore", {})),
            "raw_log_path": relative_or_absolute(repo, log),
        })
    (output / "report.json").write_text(json.dumps({
        "schema_version": SCHEMA_VERSION, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tools": results,
    }, indent=2, sort_keys=True) + "\n")
    return int(any(result["status"] != "PASSED" for result in results))


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
        if not isinstance(tool.get("cwd", "."), str):
            raise ValueError(f"invalid cwd for {tool_id}")
        commands = tool.get("commands")
        if not isinstance(commands, list) or not commands or any(
            not isinstance(command, list) or not command or not all(isinstance(arg, str) and arg for arg in command)
            for command in commands
        ):
            raise ValueError(f"invalid commands for {tool_id}")
        command_cwds = tool.get("command_cwds")
        if command_cwds is not None and (
            not isinstance(command_cwds, list)
            or len(command_cwds) != len(commands)
            or not all(isinstance(path, str) for path in command_cwds)
        ):
            raise ValueError(f"invalid command_cwds for {tool_id}")


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

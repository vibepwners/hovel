from pathlib import Path

import check_repo_policy


def line_of(path: Path, expected: str) -> int:
    return path.read_text(encoding="utf-8").splitlines().index(expected) + 1


def write_taskfile(
    repo: Path,
    ci_command: str = "      - task: docs:check",
    docs_check_command: str = "      - task: docs:test",
) -> None:
    (repo / "Taskfile.yml").write_text(
        f"""version: "3"

tasks:
  ci:
    desc: Remote-compatible gate.
    cmds:
{ci_command}

  docs:check:
    cmds:
{docs_check_command}
""",
        encoding="utf-8",
    )


def test_hermeticity_accepts_declared_host_boundary(tmp_path: Path) -> None:
    write_taskfile(tmp_path)
    host_rule = tmp_path / "docs/demo/demo_defs.bzl"
    host_rule.parent.mkdir(parents=True)
    host_rule.write_text(
        'execution_requirements = {"no-remote": "1", "no-sandbox": "1"}\nuse_default_shell_env = True\n',
        encoding="utf-8",
    )

    assert check_repo_policy.check_hermeticity(tmp_path) == []


def test_hermeticity_rejects_unallowlisted_execution_setting(tmp_path: Path) -> None:
    write_taskfile(tmp_path)
    build = tmp_path / "sdk/BUILD.bazel"
    build.parent.mkdir(parents=True)
    build.write_text("use_default_shell_env = True\n", encoding="utf-8")

    violations = check_repo_policy.check_hermeticity(tmp_path)

    assert [(item.path, item.line) for item in violations] == [(build, 1)]
    assert "non-hermetic Bazel setting" in violations[0].message


def test_hermeticity_ignores_local_tool_cache(tmp_path: Path) -> None:
    write_taskfile(tmp_path)
    generated = tmp_path / ".local/tools/BUILD.bazel"
    generated.parent.mkdir(parents=True)
    generated.write_text("use_default_shell_env = True\n", encoding="utf-8")

    assert check_repo_policy.check_hermeticity(tmp_path) == []


def test_repository_walk_prunes_local_tool_cache(tmp_path: Path) -> None:
    source = tmp_path / "core" / "source.go"
    cached = tmp_path / ".local" / "bazel" / "embedded_tools" / "source.go"
    source.parent.mkdir(parents=True)
    cached.parent.mkdir(parents=True)
    source.write_text("", encoding="utf-8")
    cached.write_text("", encoding="utf-8")

    assert check_repo_policy.repository_files(tmp_path) == [source]


def test_hermeticity_rejects_host_docs_from_remote_gate(tmp_path: Path) -> None:
    write_taskfile(tmp_path, "      - task: docs:demos")

    violations = check_repo_policy.check_hermeticity(tmp_path)

    assert len(violations) == 1
    taskfile = tmp_path / "Taskfile.yml"
    assert violations[0].path == taskfile
    assert violations[0].line == line_of(taskfile, "      - task: docs:demos")
    assert "host-service task 'docs:demos'" in violations[0].message


def test_hermeticity_rejects_host_docs_from_docs_check(tmp_path: Path) -> None:
    write_taskfile(tmp_path, docs_check_command="      - task: docs:demos:all")

    violations = check_repo_policy.check_hermeticity(tmp_path)

    assert len(violations) == 1
    taskfile = tmp_path / "Taskfile.yml"
    assert violations[0].path == taskfile
    assert violations[0].line == line_of(taskfile, "      - task: docs:demos:all")
    assert "remote-compatible task 'docs:check'" in violations[0].message
    assert "host-service task 'docs:demos:all'" in violations[0].message

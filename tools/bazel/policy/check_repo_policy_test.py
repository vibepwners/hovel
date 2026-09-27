from pathlib import Path

import check_repo_policy


def line_of(path: Path, expected: str) -> int:
    return path.read_text(encoding="utf-8").splitlines().index(expected) + 1


def write_aspect_check(repo: Path, command: str = "//:docs_test") -> None:
    path = repo / ".aspect/check.axl"
    path.parent.mkdir(parents=True)
    path.write_text(f'checks = ["{command}"]\n', encoding="utf-8")


def write_hermetic_cc_config(repo: Path, workspace: str = "") -> None:
    root = repo / workspace
    root.mkdir(parents=True, exist_ok=True)
    (root / "MODULE.bazel").write_text(
        check_repo_policy.HERMETIC_CC_VERSION
        + "\n"
        + "\n".join(check_repo_policy.HERMETIC_CC_TOOLCHAINS)
        + "\n",
        encoding="utf-8",
    )
    (root / ".bazelrc").write_text(
        check_repo_policy.LOCAL_CC_DETECTION_DISABLED + "\n",
        encoding="utf-8",
    )


def test_hermetic_cc_configuration_is_required_in_both_workspaces(tmp_path: Path) -> None:
    write_hermetic_cc_config(tmp_path)
    write_hermetic_cc_config(tmp_path, "core")

    assert check_repo_policy.check_hermetic_cc_toolchain(tmp_path) == []

    (tmp_path / "core/.bazelrc").write_text("", encoding="utf-8")
    violations = check_repo_policy.check_hermetic_cc_toolchain(tmp_path)

    assert len(violations) == 1
    assert violations[0].path == tmp_path / "core/.bazelrc"
    assert "auto-detection" in violations[0].message


def test_hermeticity_accepts_declared_host_boundary(tmp_path: Path) -> None:
    write_aspect_check(tmp_path)
    host_rule = tmp_path / "docs/demo/demo_defs.bzl"
    host_rule.parent.mkdir(parents=True)
    host_rule.write_text(
        'execution_requirements = {"no-remote": "1", "no-sandbox": "1"}\nuse_default_shell_env = True\n',
        encoding="utf-8",
    )

    assert check_repo_policy.check_hermeticity(tmp_path) == []


def test_hermeticity_rejects_unallowlisted_execution_setting(tmp_path: Path) -> None:
    write_aspect_check(tmp_path)
    build = tmp_path / "sdk/BUILD.bazel"
    build.parent.mkdir(parents=True)
    build.write_text("use_default_shell_env = True\n", encoding="utf-8")

    violations = check_repo_policy.check_hermeticity(tmp_path)

    assert [(item.path, item.line) for item in violations] == [(build, 1)]
    assert "non-hermetic Bazel setting" in violations[0].message


def test_hermeticity_ignores_local_tool_cache(tmp_path: Path) -> None:
    write_aspect_check(tmp_path)
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
    write_aspect_check(tmp_path, "//docs/tools/demo:materialize_docs_demo_outputs")

    violations = check_repo_policy.check_hermeticity(tmp_path)

    assert len(violations) == 1
    check_file = tmp_path / ".aspect/check.axl"
    assert violations[0].path == check_file
    assert violations[0].line == 1
    assert "host-service target" in violations[0].message


def test_hermeticity_rejects_host_docs_from_docs_check(tmp_path: Path) -> None:
    write_aspect_check(tmp_path, "//docs/tools/demo:materialize_squatter_wine_demo_outputs")

    violations = check_repo_policy.check_hermeticity(tmp_path)

    assert len(violations) == 1
    check_file = tmp_path / ".aspect/check.axl"
    assert violations[0].path == check_file
    assert violations[0].line == 1
    assert "host-service target" in violations[0].message


def test_action_environment_does_not_satisfy_repository_configuration(tmp_path: Path) -> None:
    write_hermetic_cc_config(tmp_path)
    (tmp_path / ".bazelrc").write_text(
        "build --action_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1\n", encoding="utf-8"
    )

    violations = check_repo_policy.check_hermetic_cc_toolchain(tmp_path)

    assert len(violations) == 1
    assert "auto-detection" in violations[0].message


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))

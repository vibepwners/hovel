"""Packaging metadata regression tests for the PyPI-facing Python packages."""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

try:
    from ._test_env import PROJECT_ROOT as REPO_ROOT
except ImportError:  # pragma: no cover - supports direct module import
    from _test_env import PROJECT_ROOT as REPO_ROOT


def _load_pyproject(package_dir: str) -> dict:
    pyproject = REPO_ROOT / package_dir / "pyproject.toml"
    return tomllib.loads(pyproject.read_text())


EXPECTED_AUTHORS = [
    {"name": "William Born", "email": "william.born.git@gmail.com"},
    {"name": "Ricardo Rivera", "email": "ricardo.rivera@zetier.com"},
]


class TestPicblobsPackaging:
    def test_package_versions_are_in_sync(self) -> None:
        import picblobs

        lib_project = _load_pyproject("python")["project"]
        cli_project = _load_pyproject("python_cli")["project"]

        assert lib_project["version"] == picblobs.__version__
        assert cli_project["version"] == picblobs.__version__
        assert f"picblobs>={picblobs.__version__}" in cli_project["dependencies"]

    def test_library_readme_is_not_blank(self) -> None:
        readme = REPO_ROOT / "python" / "README.md"
        assert readme.read_text().strip()

    def test_library_metadata_has_release_fields(self) -> None:
        project = _load_pyproject("python")["project"]

        assert project["readme"] == "README.md"
        assert project["authors"] == EXPECTED_AUTHORS
        assert project["classifiers"]
        assert project["keywords"]
        assert project["urls"]["Homepage"]
        assert project["urls"]["Documentation"]
        assert project["urls"]["Issues"]
        dev_deps = project["optional-dependencies"]["dev"]
        assert "clang-format==22.1.1" in dev_deps
        assert any(dep.startswith("lefthook>=") for dep in dev_deps)
        assert any(dep.startswith("lizard>=") for dep in dev_deps)
        assert any(dep.startswith("tomli>=") for dep in dev_deps)
        assert any(dep.startswith("ruff>=") for dep in dev_deps)

    def test_library_wheel_excludes_dev_so_tree(self) -> None:
        pyproject = _load_pyproject("python")
        wheel_target = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]

        assert wheel_target["packages"] == ["picblobs"]
        assert (
            "picblobs/blobs/*.bin" in pyproject["tool"]["hatch"]["build"]["artifacts"]
        )
        assert "picblobs/_blobs/**" in pyproject["tool"]["hatch"]["build"]["exclude"]
        assert "force-include" not in wheel_target


class TestPicblobsCliPackaging:
    def test_cli_readme_is_not_blank(self) -> None:
        readme = REPO_ROOT / "python_cli" / "README.md"
        assert readme.read_text().strip()

    def test_cli_metadata_has_release_fields(self) -> None:
        project = _load_pyproject("python_cli")["project"]

        assert project["readme"] == "README.md"
        assert project["authors"] == EXPECTED_AUTHORS
        assert project["classifiers"]
        assert project["keywords"]
        assert project["urls"]["Homepage"]
        assert project["urls"]["Documentation"]
        assert project["urls"]["Issues"]

    def test_cli_wheel_relies_on_package_tree_inclusion(self) -> None:
        wheel_target = _load_pyproject("python_cli")["tool"]["hatch"]["build"][
            "targets"
        ]["wheel"]

        assert wheel_target["packages"] == ["picblobs_cli"]
        assert "force-include" not in wheel_target


class TestRepoTooling:
    def test_setup_installs_lefthook(self) -> None:
        # sourceme delegates all setup to `task setup`, which installs hooks.
        sourceme = (REPO_ROOT / "sourceme").read_text()
        assert "task setup" in sourceme

        taskfile = (REPO_ROOT / "Taskfile.yml").read_text()
        assert "lefthook install" in taskfile

    def test_lefthook_covers_repo_quality_entrypoints(self) -> None:
        content = (REPO_ROOT / "lefthook.yml").read_text()

        assert "pre-commit:" in content
        assert "pre-push:" in content
        assert "tools/fmt.py" in content
        assert "tools/lint.py" in content
        assert "tools/c_lint_check.sh" in content

    def test_fmt_uses_repo_clang_format_config(self) -> None:
        content = (REPO_ROOT / "tools" / "fmt.py").read_text()

        assert ".clang-format" in content
        assert "--style=" in content

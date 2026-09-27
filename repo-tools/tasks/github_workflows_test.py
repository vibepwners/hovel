from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path


FILES = {Path(argument).as_posix(): Path(argument).read_text(encoding="utf-8") for argument in sys.argv[1:]}
FILES = {(path if path.endswith("action.yml") else Path(path).name): content for path, content in FILES.items()}
sys.argv[1:] = []


def test_every_remote_action_is_pinned_by_commit() -> None:
    for name, content in FILES.items():
        for action in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", content):
            if action.startswith("./"):
                continue
            assert re.search(r"@[0-9a-f]{40}$", action), (name, action)


def test_release_is_tag_driven_and_ordered() -> None:
    workflow = FILES["release.yml"]
    assert 'tags: ["v*"]' in workflow
    assert "release:" not in workflow.split("permissions:", 1)[0]
    assert "aspect hovel-check" in workflow
    assert "needs: [verify, build-picblobs, publish-picblobs]" in workflow
    assert "needs: [verify, publish-hovel, publish-sdk, publish-picblobs-cli, build-modules, build-agent]" in workflow
    assert workflow.count("needs: [verify, reproducibility]") == 5
    assert workflow.count("uses: ./.github/actions/verify-reproducible-artifacts") == 5
    assert "ref: ${{ needs.verify.outputs.source-sha }}" in workflow
    assert workflow.index("publish-picblobs:") < workflow.index("publish-picblobs-cli:")
    assert workflow.index("publish-picblobs-cli:") < workflow.index("github-release:")


def test_release_keeps_publisher_identities_and_minimal_permissions() -> None:
    workflow = FILES["release.yml"]
    for environment in ("pypi", "pypi-picblobs", "pypi-picblobs-cli"):
        assert f"environment: {environment}" in workflow
    assert workflow.count("id-token: write") == 4
    assert workflow.count("contents: write") == 1
    assert workflow.count("pypa/gh-action-pypi-publish@") == 4
    assert workflow.count("skip-existing: true") == 4
    assert workflow.count("attestations: true") == 4
    assert workflow.count("needs.verify.outputs.picblobs-changed == 'true'") == 4


def test_reproducibility_is_serial_on_separate_runners_and_not_a_pr_gate() -> None:
    workflow = FILES["reproducibility.yml"]
    assert "schedule:" in workflow and "workflow_dispatch:" in workflow and "workflow_call:" in workflow
    assert "pull_request:" not in workflow
    assert "needs: first" in workflow
    assert workflow.count("uses: ./.github/workflows/repro-build.yml") == 2
    rebuild = FILES["repro-build.yml"]
    assert "aspect hovel-repro prepare" in rebuild
    assert "aspect hovel-repro build" in rebuild
    assert "aspect hovel-repro verify" in rebuild


def test_release_builds_and_smokes_only_through_aspect() -> None:
    workflow = FILES["release.yml"]
    for kind in ("hovel", "sdk", "picblobs-cli", "modules", "agent"):
        assert f"aspect hovel-release {kind}" in workflow
    assert workflow.count("release_tool -- smoke") == 4
    assert "release_tool -- stage-assets" in workflow
    assert "release_tool -- manifest" in workflow
    assert workflow.count("release_tool -- verify-pypi") == 4
    assert "pip install" not in workflow
    assert "setup-python" not in workflow
    assert "setup-go" not in workflow


def test_repository_workflows_share_one_setup_action() -> None:
    for filename in ("ci.yml", "pages.yml", "release.yml"):
        assert "./.github/actions/setup-hovel" in FILES[filename]
        assert "aspect-build/setup-aspect@" not in FILES[filename]
        assert "actions/cache@" not in FILES[filename]


def test_ci_has_complete_scopes_and_bounded_jobs() -> None:
    workflow = FILES["ci.yml"]
    for scope in ("repo", "core", "sdk", "module-examples", "modules", "agent"):
        assert f"- scope: {scope}\n" in workflow
    assert "aspect hovel-report" in workflow
    assert "aspect hovel-ci wine" in workflow
    assert "fail-fast: false" in workflow
    assert "id-token: write" not in workflow
    assert "pull_request_target" not in workflow
    assert "merge_group:" in workflow
    assert workflow.count("timeout-minutes:") == workflow.count("runs-on:")


def test_private_wine_auth_is_limited_to_image_preparation() -> None:
    workflow = FILES["ci.yml"]
    wine = workflow.split("  squatter-wine:\n", 1)[1]
    assert workflow.count("packages: read") == 1
    assert "packages: read" in wine
    prepare, runtime = wine.split("      - name: Verify Wine integration and materialize demo", 1)
    assert "GITHUB_TOKEN: ${{ github.token }}" in prepare
    assert "aspect hovel-ci image-prepare" in prepare
    assert "GITHUB_TOKEN" not in runtime


def test_every_build_job_configures_and_cleans_up_buildbuddy() -> None:
    for filename in ("ci.yml", "release.yml"):
        workflow = FILES[filename]
        setups = workflow.count("uses: ./.github/actions/setup-hovel")
        assert setups == workflow.count("buildbuddy-api-key: ${{ secrets.BUILDBUDDY_API_KEY }}")
        assert setups == workflow.count("uses: ./.github/actions/finish-hovel")
        assert "persist-credentials: false" in workflow


def test_pages_promotes_only_trusted_successful_ci_artifacts() -> None:
    workflow = FILES["pages.yml"]
    assert "github.event.workflow_run.event == 'push'" in workflow
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in workflow
    assert "run-id: ${{ github.event.workflow_run.id }}" in workflow
    assert "name: docs-site" in workflow


def test_setup_does_not_mix_disk_action_cache_with_remote_execution() -> None:
    setup = next(content for name, content in FILES.items() if name.endswith("setup-hovel/action.yml"))
    assert 'disk-cache: "false"' in setup
    assert 'repository-cache: "false"' in setup
    assert 'launcher-version: "2026.33.3"' in setup
    assert setup.count("${{ inputs.cache-family }}") == 2
    assert "'**/*.bzl'" in setup
    for name in ("ci.yml", "release.yml", "pages.yml"):
        workflow = FILES[name]
        assert workflow.count("cache-family:") == workflow.count("buildbuddy-api-key:")


if __name__ == "__main__":
    suite = unittest.TestSuite(unittest.FunctionTestCase(test) for name, test in list(globals().items()) if name.startswith("test_"))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())

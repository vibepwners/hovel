"""Regression tests for deterministic Python distribution metadata."""

from __future__ import annotations

import pytest
from build_dist import metadata


def test_long_summary_is_not_folded() -> None:
    description = (
        "Click CLI + non-Linux cross-compiled runners and verifier fixtures "
        "for picblobs"
    )
    project = {
        "name": "picblobs-cli",
        "version": "0.1.8",
        "description": description,
        "requires-python": ">=3.10",
        "license": "Apache-2.0",
    }

    metadata_text = metadata(project)

    if f"Summary: {description}\n" not in metadata_text:
        pytest.fail("Summary was not serialized on one physical line")
    if "\n " in metadata_text:
        pytest.fail("distribution metadata contains a folded header")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))

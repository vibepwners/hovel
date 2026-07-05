"""Payload test definitions derived from the canonical registry.

This module keeps pytest payload expectations and platform matrices aligned
with ``tools/registry.py`` instead of maintaining a separate handwritten
shadow registry in the test suite.
"""

from __future__ import annotations

import dataclasses

try:
    from ._test_env import prepend_source_paths
except ImportError:  # pragma: no cover - pytest may import this as top-level
    from _test_env import prepend_source_paths

prepend_source_paths()

from tools.registry import BLOB_TYPES, OPERATING_SYSTEMS, blob_public_name  # noqa: E402


@dataclasses.dataclass(frozen=True)
class PayloadExpectation:
    """What a payload should produce when executed."""

    blob_type: str
    stdout: bytes | None = None
    stdout_contains: bytes | None = None
    exit_code: int = 0
    needs_config: bool = False
    needs_infrastructure: bool = False
    timeout: float = 30.0


_INFRA_BLOBS = {"stager_tcp", "stager_fd", "stager_pipe"}


def _build_expectations() -> dict[str, PayloadExpectation]:
    expectations: dict[str, PayloadExpectation] = {}
    for blob in BLOB_TYPES.values():
        if not blob.pytest_enabled:
            continue
        public_name = blob_public_name(blob)
        candidate = PayloadExpectation(
            blob_type=public_name,
            stdout=blob.pytest_stdout,
            stdout_contains=blob.pytest_stdout_contains,
            exit_code=blob.pytest_exit_code,
            needs_config=blob.has_config,
            needs_infrastructure=public_name in _INFRA_BLOBS,
            timeout=blob.pytest_timeout,
        )
        existing = expectations.get(public_name)
        if existing is not None and existing != candidate:
            raise ValueError(
                f"Conflicting pytest expectations for public blob {public_name!r}: "
                f"{existing!r} vs {candidate!r}"
            )
        expectations[public_name] = candidate
    return expectations


def _build_payload_platforms() -> dict[str, list[str]]:
    platforms: dict[str, set[str]] = {}
    for blob in BLOB_TYPES.values():
        if not blob.pytest_enabled:
            continue
        public_name = blob_public_name(blob)
        dest = platforms.setdefault(public_name, set())
        dest.update(blob.platforms.keys())
    return {name: sorted(os_list) for name, os_list in platforms.items()}


EXPECTATIONS: dict[str, PayloadExpectation] = _build_expectations()
PAYLOAD_PLATFORMS: dict[str, list[str]] = _build_payload_platforms()


RUNNER_TYPE: dict[str, str] = {
    os_name: os_def.runner_type or os_name
    for os_name, os_def in OPERATING_SYSTEMS.items()
}


def runtime_test_arches(os_name: str) -> list[str]:
    """Return arches that are expected to execute in pytest for an OS.

    FreeBSD runtime execution is intentionally limited to x86_64. Other
    FreeBSD blob arches may still be built or structurally validated, but
    ptrace-based runtime execution is not a supported pytest path for them.
    """
    os_entry = OPERATING_SYSTEMS.get(os_name)
    if os_entry is None:
        return []
    if os_name == "freebsd":
        return ["x86_64"]
    return list(os_entry.architectures)


def all_payload_combos() -> list[tuple[str, str, str]]:
    """Return all (blob_type, os, arch) combos from the canonical blob registry."""
    combos = []
    for blob_type, os_list in PAYLOAD_PLATFORMS.items():
        for os_name in os_list:
            os_entry = OPERATING_SYSTEMS.get(os_name)
            if os_entry is None:
                continue
            combos.extend((blob_type, os_name, arch) for arch in os_entry.architectures)
    return sorted(combos)

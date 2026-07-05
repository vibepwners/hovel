# ADR-008: uv for Python Project Management and Packaging

## Status
Accepted

## Context

picblobs needs a Python project management tool for dependency management, virtual environment management, and wheel building. The Python packaging ecosystem has several options.

## Decision

uv SHALL be used for Python project management, dependency resolution, and wheel building.

## Alternatives Considered

- **Hatch**: Mature, well-designed, excellent environment management. A strong candidate but uv's speed advantage and growing ecosystem momentum made uv preferred.
- **Poetry**: Popular but historically slow dependency resolution, and its custom lockfile format is less standard. Rejected.
- **PDM**: Standards-compliant, PEP 621. Good option but smaller community than uv. Rejected.
- **Setuptools + pip**: The classic approach. Works but lacks modern lockfile support, environment management, and developer ergonomics. Rejected.

## Consequences

- Developers need uv installed (a single binary, easy to install).
- `pyproject.toml` uses standard PEP 621 metadata (uv is standards-compliant).
- `uv.lock` provides reproducible dependency resolution.
- uv's speed makes wheel builds and CI installs fast.

## Related Requirements
- REQ-017

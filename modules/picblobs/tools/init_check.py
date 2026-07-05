#!/usr/bin/env python3
"""Detect local variables declared without an initializer.

House rule: every local variable shall be initialized at its declaration
(`= 0` for scalars/pointers, `= {0}` for aggregates).

This complements clang-tidy's ``cppcoreguidelines-init-variables`` check, which
only handles scalars and pointers and *silently skips* aggregates. This tool
uses libclang to flag uninitialized locals of every type, and by default
reports exactly the gap clang-tidy misses: arrays, structs, and unions. Pass
``--all`` to also report the scalar/pointer cases (useful when running this
detector standalone, without the clang-tidy layer).

Detection only — it never modifies source files.

Usage:
    python tools/init_check.py                  # scan src/ + tests/ (aggregates)
    python tools/init_check.py --all            # also include scalars/pointers
    python tools/init_check.py src/payload/x.c  # only the given files

Exit status is 1 when any uninitialized declaration is found, else 0.
A missing libclang is a soft skip, unless PICBLOBS_REQUIRE_LINT_TOOLS is set
(CI sets it), in which case it is a hard error — matching the C lint aspect.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from quality_paths import PROJECT_ROOT, collect_files

if TYPE_CHECKING:
    from collections.abc import Iterator

log = logging.getLogger("init_check")

C_ROOTS = ["src", "tests"]
EXCLUDE = {
    "bazel-bin",
    "bazel-out",
    "bazel-testlogs",
    "bazel-pic",
    "bazel-picblobs",
    ".venv",
    "__pycache__",
    ".cache",
    "node_modules",
    "dist",
    "build",
}

# Vendored third-party sources are kept close to upstream and are not subject to
# the project's initialization rule (mirrors the NOLINT block in tweetnacl.h).
VENDORED = {"src/include/picblobs/crypto/tweetnacl.h"}

# Compile flags mirror the freestanding toolchain feature and the clang-tidy
# aspect (see bazel/lint.bzl). libclang needs them explicitly; without the
# include path the picblobs headers will not resolve.
BASE_ARGS = [
    "-x",
    "c",
    "-std=c11",
    "-ffreestanding",
    "-fno-builtin",
    "-fPIC",
    f"-I{PROJECT_ROOT / 'src' / 'include'}",
]


class Finding(NamedTuple):
    path: str
    line: int
    col: int
    name: str
    typename: str
    aggregate: bool


def _load_cindex():
    """Import clang.cindex and bind the initializer query, or return None."""
    try:
        from clang import cindex
    except ImportError:
        return None
    try:
        lib = cindex.conf.lib
        # clang_Cursor_getVarDeclInitializer: CXCursor -> CXCursor (null if none).
        lib.clang_Cursor_getVarDeclInitializer.argtypes = [cindex.Cursor]
        lib.clang_Cursor_getVarDeclInitializer.restype = cindex.Cursor
        # Probe that the native library actually loads.
        cindex.Index.create()
    except Exception as exc:
        log.debug("libclang unavailable: %s", exc)
        return None
    return cindex


def _has_initializer(cindex, cursor) -> bool:
    lib = cindex.conf.lib
    init = lib.clang_Cursor_getVarDeclInitializer(cursor)
    return not lib.clang_Cursor_isNull(init)


def _is_aggregate(cindex, cursor) -> bool:
    kind = cursor.type.get_canonical().kind
    tk = cindex.TypeKind
    return kind in {
        tk.CONSTANTARRAY,
        tk.INCOMPLETEARRAY,
        tk.VARIABLEARRAY,
        tk.DEPENDENTSIZEDARRAY,
        tk.RECORD,
    }


def _compile_args(path: Path) -> list[str]:
    # The runner sources include "start/<arch>.h" relative to their own dir.
    return [*BASE_ARGS, f"-I{path.parent}"]


def _first_party(path_str: str | None) -> Path | None:
    """Return the repo-relative-safe Path for a first-party, non-vendored file."""
    if not path_str:
        return None
    path = Path(path_str).resolve()
    try:
        rel = path.relative_to(PROJECT_ROOT)
    except ValueError:
        return None  # system / out-of-tree header
    if any(part in EXCLUDE for part in rel.parts):
        return None
    if str(rel) in VENDORED:
        return None
    return rel


def _iter_local_vardecls(cindex, tu) -> Iterator:
    """Yield VAR_DECL cursors that are automatic-storage function locals."""
    ck = cindex.CursorKind
    sc = cindex.StorageClass
    for fn in tu.cursor.walk_preorder():
        if fn.kind != ck.FUNCTION_DECL or not fn.is_definition():
            continue
        for node in fn.walk_preorder():
            if node.kind != ck.VAR_DECL:
                continue
            # Static and extern locals are zero-initialized by C, never
            # indeterminate — the rule targets automatic storage only.
            if node.storage_class in (sc.STATIC, sc.EXTERN):
                continue
            yield node


def scan_file(cindex, path: Path) -> list[Finding]:
    index = cindex.Index.create()
    try:
        tu = index.parse(str(path), args=_compile_args(path))
    except cindex.TranslationUnitLoadError as exc:
        log.warning("could not parse %s: %s", path, exc)
        return []

    findings: list[Finding] = []
    for cursor in _iter_local_vardecls(cindex, tu):
        if _has_initializer(cindex, cursor):
            continue
        loc = cursor.location
        rel = _first_party(loc.file.name if loc.file else None)
        if rel is None:
            continue
        findings.append(
            Finding(
                path=str(rel),
                line=loc.line,
                col=loc.column,
                name=cursor.spelling,
                typename=cursor.type.spelling,
                aggregate=_is_aggregate(cindex, cursor),
            )
        )
    return findings


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="C files or dirs (default: src tests)")
    parser.add_argument(
        "--all",
        action="store_true",
        help="also report scalars/pointers (default: aggregates only)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="accepted for CI symmetry; behavior is identical",
    )
    return parser.parse_args(argv)


def _missing_libclang(cindex) -> bool:
    """Report the skip/error for an absent libclang. Returns True when absent."""
    if cindex is not None:
        return False
    msg = "init_check: libclang (clang.cindex) not available"
    if os.environ.get("PICBLOBS_REQUIRE_LINT_TOOLS"):
        log.error("%s — required by PICBLOBS_REQUIRE_LINT_TOOLS", msg)
    else:
        log.warning("%s — skipping (pip install libclang)", msg)
    return True


def collect_findings(
    cindex, files: list[Path], *, include_scalars: bool
) -> list[Finding]:
    """Scan files, dedup across translation units, and filter by scope."""
    seen: set[tuple[str, int, int]] = set()
    findings: list[Finding] = []
    for path in files:
        for finding in scan_file(cindex, path):
            key = (finding.path, finding.line, finding.col)
            if key in seen:
                continue  # header pulled into multiple TUs
            seen.add(key)
            if include_scalars or finding.aggregate:
                findings.append(finding)
    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings


def _report(findings: list[Finding]) -> None:
    for f in findings:
        kind = "aggregate" if f.aggregate else "scalar"
        log.info(
            "%s:%d:%d: '%s' (%s) declared without initializer [%s]",
            f.path,
            f.line,
            f.col,
            f.name,
            f.typename,
            kind,
        )


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args(argv)

    cindex = _load_cindex()
    if _missing_libclang(cindex):
        return 1 if os.environ.get("PICBLOBS_REQUIRE_LINT_TOOLS") else 0

    files = collect_files(args.paths, roots=C_ROOTS, extensions={".c"}, exclude=EXCLUDE)
    findings = collect_findings(cindex, files, include_scalars=args.all)
    _report(findings)

    scope = "uninitialized locals" if args.all else "uninitialized aggregates"
    if findings:
        log.info("init_check: %d %s found", len(findings), scope)
        return 1
    log.info("init_check: no %s", scope)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

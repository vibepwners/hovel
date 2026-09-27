"""Cacheable source checks consumed by both CI and the report."""

LINT_RESULTS = [
    "//tools/lint:" + name + "_result"
    for name in [
        "core_gofmt",
        "core_golangci",
        "core_gazelle",
        "gofmt_modules",
        "buildifier",
        "policy",
        "ruff",
        "mypy",
        "pydoclint",
        "rustfmt",
        "picblobs_ruff",
        "picblobs_clang_format",
        "picblobs_lizard",
    ]
]

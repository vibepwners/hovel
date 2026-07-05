"""Hermetic cppcheck package for picblobs Bazel tests."""

_CPPCHECK_URLS = [
    "https://github.com/danmar/cppcheck/archive/refs/tags/2.21.0.tar.gz",
]

_CPPCHECK_SHA256 = "f028ff75ca5372738f3737c8b3e8611426a6526b6aea2ef01301ab0f5902f044"

def _build_file():
    return """\
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

package(default_visibility = ["//visibility:public"])

sh_binary(
    name = "cppcheck",
    srcs = ["bin/cppcheck"],
    data = [
        ":cppcheck.real",
        ":support_files",
    ],
)

filegroup(
    name = "support_files",
    srcs = glob([
        "addons/**",
        "cfg/**",
        "platforms/**",
    ]),
)
"""

def _cppcheck_repo_impl(ctx):
    ctx.download_and_extract(
        url = ctx.attr.urls,
        sha256 = ctx.attr.sha256,
        stripPrefix = ctx.attr.strip_prefix,
    )
    result = ctx.execute(
        [
            "make",
            "-j{}".format(ctx.attr.jobs),
            "cppcheck",
            "HAVE_RULES=",
            "MATCHCOMPILER=",
            "CXXFLAGS=-O2 -DNDEBUG",
        ],
        timeout = 1200,
    )
    if result.return_code:
        fail("failed to build cppcheck: {}\n{}".format(result.stderr, result.stdout))
    result = ctx.execute(["mv", "cppcheck", "cppcheck.real"])
    if result.return_code:
        fail("failed to stage cppcheck binary: {}\n{}".format(result.stderr, result.stdout))
    ctx.file("bin/cppcheck", """\
#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
exec "$root/cppcheck.real" "$@"
""", executable = True)
    ctx.file("BUILD.bazel", _build_file())

cppcheck_repo = repository_rule(
    implementation = _cppcheck_repo_impl,
    attrs = {
        "jobs": attr.int(default = 2),
        "sha256": attr.string(default = _CPPCHECK_SHA256),
        "strip_prefix": attr.string(default = "cppcheck-2.21.0"),
        "urls": attr.string_list(default = _CPPCHECK_URLS),
    },
)

def _cppcheck_impl(_module_ctx):
    cppcheck_repo(name = "cppcheck_linux_x86_64")

cppcheck = module_extension(
    implementation = _cppcheck_impl,
)

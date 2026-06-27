"""Bazel-backed clang-tidy checks for Squatter C sources."""

_MINGW_INCLUDE_MARKER = "@mingw_i686//:i686-w64-mingw32/include/winsock2.h"
_MINGW_TOOLCHAIN = "@mingw_i686//:toolchain_all"
_RUNNER = "//tools/lint:run_squatter_clang_tidy.sh"

def _check_name(src):
    return "clang_tidy_" + src.replace("/", "_").replace(".", "_")

def squatter_clang_tidy(name, srcs, hdrs):
    """Creates one cacheable clang-tidy action per C source file."""

    checks = []
    package_include = native.package_name()

    for src in srcs:
        check = _check_name(src)
        native.genrule(
            name = check,
            srcs = [src] + hdrs + [
                _MINGW_INCLUDE_MARKER,
                _MINGW_TOOLCHAIN,
            ],
            outs = ["clang_tidy/%s.stamp" % check],
            cmd = "'$(location %s)' '$(location %s)' '$(location %s)' '%s' && touch '$@'" % (
                _RUNNER,
                src,
                _MINGW_INCLUDE_MARKER,
                package_include,
            ),
            tags = ["manual"],
            tools = [_RUNNER],
        )
        checks.append(":" + check)

    native.filegroup(
        name = name,
        srcs = checks,
        tags = ["manual"],
    )

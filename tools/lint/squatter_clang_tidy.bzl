"""Bazel-backed clang-tidy checks for Squatter C sources."""

_MINGW_INCLUDE_MARKER = "@mingw_i686//:i686-w64-mingw32/include/winsock2.h"
_MINGW_TOOLCHAIN = "@mingw_i686//:toolchain_all"
_RUNNER = "//tools/lint:run_squatter_clang_tidy"

def _check_name(src):
    return "clang_tidy_" + src.replace("/", "_").replace(".", "_")

def _tool_files(ctx):
    return depset(
        [ctx.executable._runner],
        transitive = [
            ctx.attr._runner[DefaultInfo].files,
            ctx.attr._runner[DefaultInfo].default_runfiles.files,
            ctx.attr._runner[DefaultInfo].data_runfiles.files,
        ],
    )

def _clang_tidy_check_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".stamp")
    args = ctx.actions.args()
    args.add("--stamp", out)
    args.add("--source", ctx.file.src)
    args.add("--mingw-marker", ctx.file._mingw_include_marker)
    args.add("--project-include", ctx.attr.project_include)
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [args],
        inputs = [ctx.file.src, ctx.file._mingw_include_marker] + ctx.files.hdrs + ctx.files._mingw_toolchain,
        outputs = [out],
        tools = _tool_files(ctx),
        mnemonic = "SquatterClangTidy",
        progress_message = "Running clang-tidy for %{label}",
    )
    return [DefaultInfo(files = depset([out]))]

_clang_tidy_check = rule(
    implementation = _clang_tidy_check_impl,
    attrs = {
        "hdrs": attr.label_list(allow_files = [".h"]),
        "project_include": attr.string(mandatory = True),
        "src": attr.label(allow_single_file = [".c"], mandatory = True),
        "_mingw_include_marker": attr.label(
            default = _MINGW_INCLUDE_MARKER,
            allow_single_file = True,
        ),
        "_mingw_toolchain": attr.label(
            default = _MINGW_TOOLCHAIN,
        ),
        "_runner": attr.label(
            default = _RUNNER,
            executable = True,
            cfg = "exec",
        ),
    },
)

def squatter_clang_tidy(name, srcs, hdrs):
    """Creates one cacheable clang-tidy action per C source file."""

    checks = []
    package_include = native.package_name()

    for src in srcs:
        check = _check_name(src)
        _clang_tidy_check(
            name = check,
            src = src,
            hdrs = hdrs,
            project_include = package_include,
            tags = ["manual"],
        )
        checks.append(":" + check)

    native.filegroup(
        name = name,
        srcs = checks,
        tags = ["manual"],
    )

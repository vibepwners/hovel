"""Bazel-backed clang-tidy checks for Squatter C sources."""

_MINGW_INCLUDE_MARKER = "@mingw_i686//:i686-w64-mingw32/include/winsock2.h"
_MINGW_TOOLCHAIN = "@mingw_i686//:toolchain_all"
_CLANG_TIDY = "@llvm_mingw_ucrt_linux_x86_64//:clang_tidy_bin"
_RUNNER = "//tools/lint:run_squatter_clang_tidy"

def _check_name(src):
    return "clang_tidy_" + src.replace("/", "_").replace(".", "_")

def _tool_files(ctx):
    return depset(
        [ctx.executable._runner, ctx.file._clang_tidy],
        transitive = [
            ctx.attr._clang_tidy_files[DefaultInfo].files,
            ctx.attr._runner[DefaultInfo].files,
            ctx.attr._runner[DefaultInfo].default_runfiles.files,
            ctx.attr._runner[DefaultInfo].data_runfiles.files,
        ],
    )

def _clang_tidy_check_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".stamp")
    args = ctx.actions.args()
    args.add("--clang-tidy", ctx.file._clang_tidy)
    args.add("--stamp", out)
    args.add("--source", ctx.file.src)
    args.add("--mingw-marker", ctx.file._mingw_include_marker)
    args.add("--wolfssl-marker", ctx.file.wolfssl_marker)
    args.add("--wolfssl-config", ctx.file.wolfssl_config)
    args.add("--project-include", ctx.attr.project_include)
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [args],
        inputs = [
            ctx.file.src,
            ctx.file._mingw_include_marker,
            ctx.file.wolfssl_config,
            ctx.file.wolfssl_marker,
        ] + ctx.files.hdrs + ctx.files.wolfssl_headers + ctx.files._mingw_toolchain,
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
        "wolfssl_config": attr.label(allow_single_file = [".h"], mandatory = True),
        "wolfssl_headers": attr.label(mandatory = True),
        "wolfssl_marker": attr.label(allow_single_file = [".h"], mandatory = True),
        "_mingw_include_marker": attr.label(
            default = _MINGW_INCLUDE_MARKER,
            allow_single_file = True,
        ),
        "_mingw_toolchain": attr.label(
            default = _MINGW_TOOLCHAIN,
        ),
        "_clang_tidy": attr.label(
            default = _CLANG_TIDY,
            allow_single_file = True,
            cfg = "exec",
        ),
        "_clang_tidy_files": attr.label(
            default = Label("@llvm_mingw_ucrt_linux_x86_64//:clang_tidy_files"),
            cfg = "exec",
        ),
        "_runner": attr.label(
            default = _RUNNER,
            executable = True,
            cfg = "exec",
        ),
    },
)

def squatter_clang_tidy(name, srcs, hdrs, wolfssl_config, wolfssl_headers, wolfssl_marker):
    """Creates one cacheable clang-tidy action per C source file.

    Args:
      name: Name of the aggregate filegroup target.
      srcs: C source files to check.
      hdrs: Header files made available to each clang-tidy action.
      wolfssl_config: Hovel's wolfSSL user-settings header.
      wolfssl_headers: Complete wolfSSL public header filegroup.
      wolfssl_marker: Public header used to derive wolfSSL's include root.
    """

    checks = []
    package_include = native.package_name()

    for src in srcs:
        check = _check_name(src)
        _clang_tidy_check(
            name = check,
            src = src,
            hdrs = hdrs,
            project_include = package_include,
            wolfssl_config = wolfssl_config,
            wolfssl_headers = wolfssl_headers,
            wolfssl_marker = wolfssl_marker,
            tags = ["manual"],
        )
        checks.append(":" + check)

    native.filegroup(
        name = name,
        srcs = checks,
        tags = ["manual"],
    )

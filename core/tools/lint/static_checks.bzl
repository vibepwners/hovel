"""Cacheable lint and static-analysis actions."""

def _tool_files(ctx, attrs):
    files = []
    transitive = []
    for name in attrs:
        target = getattr(ctx.attr, name)
        executable = getattr(ctx.executable, name)
        files.append(executable)
        transitive.append(target[DefaultInfo].files)
        transitive.append(target[DefaultInfo].default_runfiles.files)
        transitive.append(target[DefaultInfo].data_runfiles.files)
    return depset(files, transitive = transitive)

def _squatter_format_check_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".stamp")
    args = ctx.actions.args()
    args.add("--stamp", out)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [args],
        inputs = ctx.files.srcs + [ctx.file.clang_format_config],
        outputs = [out],
        tools = _tool_files(ctx, ["_runner"]),
        mnemonic = "SquatterFormatCheck",
        progress_message = "Checking Squatter C formatting",
    )
    return [DefaultInfo(files = depset([out]))]

squatter_format_check = rule(
    implementation = _squatter_format_check_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c", ".h"], mandatory = True),
        "clang_format_config": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "_runner": attr.label(
            default = "//tools/lint:run_squatter_format_check",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _squatter_complexity_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".stamp")
    args = ctx.actions.args()
    args.add("--stamp", out)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [args],
        inputs = ctx.files.srcs,
        outputs = [out],
        tools = _tool_files(ctx, ["_runner"]),
        mnemonic = "SquatterComplexity",
        progress_message = "Checking Squatter C complexity",
    )
    return [DefaultInfo(files = depset([out]))]

squatter_complexity = rule(
    implementation = _squatter_complexity_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c", ".h"], mandatory = True),
        "_runner": attr.label(
            default = "//tools/lint:run_squatter_complexity",
            executable = True,
            cfg = "exec",
        ),
    },
)

def _squatter_cppcheck_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".stamp")
    args = ctx.actions.args()
    args.add("--stamp", out)
    args.add("--include-dir", ctx.label.package)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [args],
        inputs = ctx.files.srcs + ctx.files.hdrs,
        outputs = [out],
        tools = _tool_files(ctx, ["_runner"]),
        mnemonic = "SquatterCppcheck",
        progress_message = "Running cppcheck for Squatter C",
    )
    return [DefaultInfo(files = depset([out]))]

squatter_cppcheck = rule(
    implementation = _squatter_cppcheck_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c"], mandatory = True),
        "hdrs": attr.label_list(allow_files = [".h"], mandatory = True),
        "_runner": attr.label(
            default = "//tools/lint:run_squatter_cppcheck",
            executable = True,
            cfg = "exec",
        ),
    },
)

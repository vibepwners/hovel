"""Helpers for gathering one binary target for a specific host platform."""

def _platform_binary_transition_impl(_settings, attr):
    return {
        "//command_line_option:platform_suffix": attr.platform_suffix,
        "//command_line_option:platforms": [str(attr.platform)],
    }

_platform_binary_transition = transition(
    implementation = _platform_binary_transition_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platform_suffix",
        "//command_line_option:platforms",
    ],
)

def _platform_binary_impl(ctx):
    src = ctx.executable.binary
    out = ctx.actions.declare_file(ctx.attr.out)
    ctx.actions.symlink(output = out, target_file = src, is_executable = True)
    return [
        DefaultInfo(
            executable = out,
            files = depset([out]),
            runfiles = ctx.runfiles(files = [out]),
        ),
    ]

platform_binary = rule(
    implementation = _platform_binary_impl,
    doc = "Build an executable dependency for one host platform and expose it under a stable filename.",
    attrs = {
        "binary": attr.label(
            cfg = _platform_binary_transition,
            executable = True,
            mandatory = True,
        ),
        "out": attr.string(mandatory = True),
        "platform": attr.label(mandatory = True),
        "platform_suffix": attr.string(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    executable = True,
)

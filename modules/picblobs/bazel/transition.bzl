"""Small platform-transition helpers for declared cross-platform artifacts."""

def _platform_transition_impl(_settings, attr):
    return {"//command_line_option:platforms": attr.platform}

_platform_transition = transition(
    implementation = _platform_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _forwarding_impl(ctx):
    files = []
    runfiles = ctx.runfiles()
    for dep in ctx.attr.deps:
        default = dep[DefaultInfo]
        files.extend(default.files.to_list())
        runfiles = runfiles.merge(default.default_runfiles)
        runfiles = runfiles.merge(default.data_runfiles)
    return [DefaultInfo(files = depset(files), runfiles = runfiles)]

platform_filegroup = rule(
    implementation = _forwarding_impl,
    doc = "Forwards files from deps built under a selected target platform.",
    attrs = {
        "deps": attr.label_list(cfg = _platform_transition),
        "platform": attr.string(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

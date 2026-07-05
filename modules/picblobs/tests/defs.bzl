"""Rules for testing cross-compiled PIC blobs on the host."""

def _arm_transition_impl(_settings, attr):
    return {"//command_line_option:platforms": attr.platform}

_arm_transition = transition(
    implementation = _arm_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _forwarding_impl(ctx):
    """Collect default outputs from transitioned deps."""
    files = []
    for dep in ctx.attr.deps:
        files.extend(dep[DefaultInfo].files.to_list())
    return [DefaultInfo(files = depset(files))]

arm_filegroup = rule(
    implementation = _forwarding_impl,
    doc = "Forwards files from deps built under an ARM platform transition.",
    attrs = {
        "deps": attr.label_list(cfg = _arm_transition),
        "platform": attr.string(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

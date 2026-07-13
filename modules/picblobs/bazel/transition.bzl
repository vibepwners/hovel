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

def _artifact_impl(ctx):
    transitioned_deps = ctx.attr.dep
    if len(transitioned_deps) != 1:
        fail("{} transition produced {} dependencies; expected exactly one".format(
            ctx.label,
            len(transitioned_deps),
        ))

    dep = transitioned_deps[0]
    files = dep[DefaultInfo].files.to_list()
    if len(files) != 1:
        fail("{} must produce exactly one file, got {}".format(dep.label, len(files)))

    source = files[0]
    suffix = "." + source.extension if source.extension else ""
    output = ctx.actions.declare_file(ctx.label.name + suffix)
    ctx.actions.symlink(
        output = output,
        target_file = source,
    )

    return [DefaultInfo(
        files = depset([output]),
        runfiles = ctx.runfiles(files = [output]),
    )]

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

platform_artifact = rule(
    implementation = _artifact_impl,
    doc = "Gives one transitioned artifact a target-unique runfiles path.",
    attrs = {
        "dep": attr.label(cfg = _platform_transition, mandatory = True),
        "platform": attr.string(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

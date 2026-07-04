"""Small file-selection helper for multi-output targets."""

def _select_file_impl(ctx):
    matches = [file for file in ctx.files.srcs if file.basename.endswith(ctx.attr.suffix)]
    if len(matches) != 1:
        fail("expected exactly one input ending in %s, got %s" % (
            ctx.attr.suffix,
            [file.short_path for file in ctx.files.srcs],
        ))

    out = ctx.actions.declare_file(ctx.attr.output_name)
    ctx.actions.symlink(output = out, target_file = matches[0])
    return [DefaultInfo(files = depset([out]))]

select_file = rule(
    implementation = _select_file_impl,
    attrs = {
        "output_name": attr.string(mandatory = True),
        "srcs": attr.label_list(allow_files = True, mandatory = True),
        "suffix": attr.string(mandatory = True),
    },
)

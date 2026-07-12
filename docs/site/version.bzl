"""Expose the repository version inside the Astro package."""

def _site_version_impl(ctx):
    output = ctx.actions.declare_file("version.txt")
    ctx.actions.symlink(output = output, target_file = ctx.file.source)
    return [DefaultInfo(files = depset([output]))]

site_version = rule(
    implementation = _site_version_impl,
    attrs = {
        "source": attr.label(allow_single_file = True, mandatory = True),
    },
)

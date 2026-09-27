"""Declared deterministic wheel outputs; materialization stays outside actions."""

def _wheel_impl(ctx):
    output = ctx.actions.declare_directory(ctx.label.name + ".dist")
    args = ctx.actions.args()
    args.add("--binary", ctx.file.binary)
    args.add("--version-file", ctx.file.version)
    args.add("--platform-tag", ctx.attr.platform_tag)
    args.add("--binary-name", ctx.attr.binary_name)
    args.add("--out-dir", output.path)
    ctx.actions.run(
        executable = ctx.executable._writer,
        arguments = [args],
        inputs = [ctx.file.binary, ctx.file.version],
        outputs = [output],
        mnemonic = "HovelWheel",
    )
    return [DefaultInfo(files = depset([output]))]

hovel_wheel = rule(
    implementation = _wheel_impl,
    attrs = {
        "binary": attr.label(mandatory = True, allow_single_file = True),
        "version": attr.label(default = "//:version_file", allow_single_file = True),
        "platform_tag": attr.string(mandatory = True),
        "binary_name": attr.string(default = "hovel"),
        "_writer": attr.label(default = ":wheel_writer", executable = True, cfg = "exec"),
    },
)

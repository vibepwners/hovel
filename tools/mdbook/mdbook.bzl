def _mdbook_book_impl(ctx):
    out = ctx.actions.declare_directory(ctx.attr.out)

    args = ctx.actions.args()
    args.add("build")
    args.add(ctx.file.config.dirname or ".")
    args.add("--dest-dir")
    args.add(out.path)

    ctx.actions.run(
        executable = ctx.file.mdbook,
        arguments = [args],
        inputs = depset(ctx.files.srcs + [ctx.file.config, ctx.file.mdbook]),
        outputs = [out],
        mnemonic = "MdBookBuild",
        progress_message = "Building mdBook %{label}",
    )

    return DefaultInfo(files = depset([out]))

mdbook_book = rule(
    implementation = _mdbook_book_impl,
    attrs = {
        "config": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "mdbook": attr.label(
            allow_single_file = True,
            cfg = "exec",
            mandatory = True,
        ),
        "out": attr.string(
            default = "book",
        ),
        "srcs": attr.label_list(
            allow_files = True,
            mandatory = True,
        ),
    },
    doc = "Builds an mdBook site as a Bazel tree artifact.",
)

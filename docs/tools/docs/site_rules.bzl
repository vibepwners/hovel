"""Rules for producing the complete documentation site as declared trees."""

def _runfiles(target):
    info = target[DefaultInfo]
    return [
        info.default_runfiles.files,
        info.data_runfiles.files,
    ]

def _sdk_docs_tree_impl(ctx):
    output = ctx.actions.declare_directory(ctx.attr.name)
    args = ctx.actions.args()
    args.add("--repo-root=.")
    args.add("--output", output.path + "/api/sdk")
    args.add("--sphinx-bin", ctx.executable.sphinx_bin)
    args.add("--go-doc-bin", ctx.executable.go_doc_bin)
    args.add("--rustdoc-bin", ctx.file.rustdoc_bin)

    ctx.actions.run(
        executable = ctx.executable.generator,
        arguments = [args],
        inputs = depset(ctx.files.sources),
        outputs = [output],
        tools = depset(
            [
                ctx.executable.go_doc_bin,
                ctx.file.rustdoc_bin,
                ctx.executable.sphinx_bin,
            ] + ctx.files.rustc_lib,
            transitive = (
                _runfiles(ctx.attr.generator) +
                _runfiles(ctx.attr.go_doc_bin) +
                _runfiles(ctx.attr.sphinx_bin)
            ),
        ),
        mnemonic = "SdkDocs",
        progress_message = "Generating native SDK documentation %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

sdk_docs_tree = rule(
    implementation = _sdk_docs_tree_impl,
    attrs = {
        "generator": attr.label(executable = True, cfg = "exec", mandatory = True),
        "go_doc_bin": attr.label(executable = True, cfg = "exec", mandatory = True),
        "rustc_lib": attr.label(allow_files = True, cfg = "exec", mandatory = True),
        "rustdoc_bin": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
        "sources": attr.label_list(allow_files = True, mandatory = True),
        "sphinx_bin": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)

def _site_tree_impl(ctx):
    output = ctx.actions.declare_directory(ctx.attr.name)
    args = ctx.actions.args()
    args.add("--output", output.path)
    args.add("--astro-site", ctx.file.astro_site.path)
    args.add("--sdk-site", ctx.file.sdk_site.path)
    args.add("--license", ctx.file.license)
    for demo in ctx.files.demos:
        args.add("--demo", demo.path + "=assets/demos/" + demo.basename)

    ctx.actions.run(
        executable = ctx.executable.assembler,
        arguments = [args],
        inputs = depset(
            [
                ctx.file.astro_site,
                ctx.file.license,
                ctx.file.sdk_site,
            ] + ctx.files.demos,
        ),
        outputs = [output],
        tools = depset(transitive = _runfiles(ctx.attr.assembler)),
        mnemonic = "AssembleDocs",
        progress_message = "Assembling documentation site %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

site_tree = rule(
    implementation = _site_tree_impl,
    attrs = {
        "assembler": attr.label(executable = True, cfg = "exec", mandatory = True),
        "astro_site": attr.label(allow_single_file = True, mandatory = True),
        "demos": attr.label_list(allow_files = True, mandatory = True),
        "license": attr.label(allow_single_file = True, mandatory = True),
        "sdk_site": attr.label(allow_single_file = True, mandatory = True),
    },
)

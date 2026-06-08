def _mingw_pe_binary_impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.out)
    args = ctx.actions.args()
    args.add_all(ctx.attr.copts)
    args.add_all([
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-nostdlib",
        "-nodefaultlibs",
    ])
    args.add_all(ctx.files.srcs)
    args.add_all(ctx.attr.linkopts)
    args.add("-Wl,--entry,%s" % ctx.attr.entry)
    args.add("-Wl,--subsystem,%s" % ctx.attr.subsystem)
    args.add("-o")
    args.add(output)

    ctx.actions.run(
        executable = ctx.executable._gcc,
        arguments = [args],
        inputs = ctx.files.srcs,
        outputs = [output],
        mnemonic = "MingwPEBinary",
        progress_message = "Building Windows PE %{output}",
        env = {
            "PATH": ctx.executable._gcc.dirname,
        },
    )
    return [DefaultInfo(files = depset([output]), executable = output)]

mingw_pe_binary = rule(
    implementation = _mingw_pe_binary_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c", ".h"]),
        "out": attr.string(mandatory = True),
        "entry": attr.string(mandatory = True),
        "subsystem": attr.string(default = "console", values = ["console", "windows"]),
        "copts": attr.string_list(),
        "linkopts": attr.string_list(),
        "_gcc": attr.label(
            default = Label("@mingw_w64_i686//:bin/i686-w64-mingw32-gcc"),
            executable = True,
            cfg = "exec",
            allow_files = True,
        ),
    },
    executable = True,
)

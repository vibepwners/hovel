"""Rules for preparing llvm-mingw inputs for Rust cross-linking."""

def _stage_llvm_mingw_libs_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)
    args = ctx.actions.args()
    args.add("--out", out.path)
    args.add_all(ctx.files.target_libs, before_each = "--target-lib")
    args.add_all(ctx.files.compiler_rt, before_each = "--compiler-rt")

    ctx.actions.run(
        mnemonic = "StageLlvmMingwLibs",
        executable = ctx.executable._tool,
        arguments = [args],
        inputs = ctx.files.target_libs + ctx.files.compiler_rt,
        outputs = [out],
    )
    return [DefaultInfo(files = depset([out]))]

stage_llvm_mingw_libs = rule(
    implementation = _stage_llvm_mingw_libs_impl,
    attrs = {
        "compiler_rt": attr.label_list(allow_files = True, mandatory = True),
        "target_libs": attr.label_list(allow_files = True, mandatory = True),
        "_tool": attr.label(
            default = "//tools/windows_rust:stage_llvm_mingw_libs_tool",
            executable = True,
            cfg = "exec",
        ),
    },
)

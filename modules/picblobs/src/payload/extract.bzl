"""Rule to extract a flat binary from an ELF .so using the CC toolchain's objcopy."""

load("@rules_cc//cc/common:cc_common.bzl", "cc_common")

def _extract_bin_impl(ctx):
    cc_toolchain = ctx.attr._cc_toolchain[cc_common.CcToolchainInfo]
    objcopy = cc_toolchain.objcopy_executable

    src = ctx.file.src
    out = ctx.actions.declare_file(src.basename.replace(".so", ".bin"))

    ctx.actions.run(
        executable = objcopy,
        arguments = ["-O", "binary", src.path, out.path],
        inputs = depset([src], transitive = [cc_toolchain.all_files]),
        outputs = [out],
        mnemonic = "ExtractBin",
        progress_message = "Extracting flat binary from %s" % src.short_path,
    )

    return [DefaultInfo(files = depset([out]))]

extract_bin = rule(
    implementation = _extract_bin_impl,
    attrs = {
        "src": attr.label(allow_single_file = [".so"], mandatory = True),
        "_cc_toolchain": attr.label(
            default = "@rules_cc//cc:current_cc_toolchain",
        ),
    },
    toolchains = ["@rules_cc//cc:toolchain_type"],
)

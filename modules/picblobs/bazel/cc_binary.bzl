"""A freestanding/hosted static binary rule built via cc_common.

`cc_binary` is unusable for our test runners: it strips the symbol table
(`-Wl,-S`) and offers no clean way to compile a single translation unit with
an instruction-set override (`-mthumb`) on top of the toolchain defaults.

The historical workaround was a `genrule` invoking `$(CC)` directly. That
works but reimplements the toolchain by hand: it duplicates the freestanding
flag list, hardcodes the GCC triple to derive the sysroot, and string-edits
`-gcc` into `-g++` for C++ links. This rule replaces all of that by going
through `cc_common.compile` / `cc_common.link`, so the toolchain supplies the
compiler, sysroot, and flags.

Two knobs the genrule needed and this rule preserves:
  * `copts` — per-target compile flags layered on top of the toolchain
    (e.g. `-mthumb` to force Thumb on an ARM-mode toolchain).
  * `freestanding` — when False, the toolchain's always-on `freestanding`
    feature is disabled for this target so a hosted binary can link against
    the standard C/C++ runtime (libstdc++, crt startup files).
"""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")  # @unused (documents actions)
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _pic_cc_binary_impl(ctx):
    cc_toolchain = find_cc_toolchain(ctx)

    unsupported_features = list(ctx.disabled_features)
    if not ctx.attr.freestanding:
        # The toolchain enables `freestanding` (-nostdlib -nostartfiles ...)
        # by default; a hosted binary must turn it off to keep the standard
        # runtime and startup files.
        unsupported_features.append("freestanding")

    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features,
        unsupported_features = unsupported_features,
    )

    compilation_contexts = [
        dep[CcInfo].compilation_context
        for dep in ctx.attr.deps
        if CcInfo in dep
    ]

    _compilation_context, compilation_outputs = cc_common.compile(
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        name = ctx.label.name,
        srcs = ctx.files.srcs,
        private_hdrs = ctx.files.hdrs,
        quote_includes = ctx.attr.quote_includes,
        includes = ctx.attr.includes,
        user_compile_flags = ctx.attr.copts,
        local_defines = ctx.attr.local_defines,
        compilation_contexts = compilation_contexts,
    )

    linking_outputs = cc_common.link(
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        name = ctx.label.name,
        compilation_outputs = compilation_outputs,
        user_link_flags = ctx.attr.linkopts,
        link_deps_statically = True,
        output_type = "executable",
    )

    executable = linking_outputs.executable
    return [DefaultInfo(
        files = depset([executable]),
        executable = executable,
    )]

pic_cc_binary = rule(
    implementation = _pic_cc_binary_impl,
    doc = "Compile and statically link a binary via the CC toolchain, " +
          "without stripping symbols.",
    attrs = {
        "srcs": attr.label_list(
            allow_files = [".c", ".cc", ".cpp", ".cxx", ".S", ".s", ".h", ".hpp"],
            doc = "C/C++ source files compiled into the binary.",
        ),
        "hdrs": attr.label_list(
            allow_files = [".h", ".hpp"],
            doc = "Private headers available during compilation.",
        ),
        "deps": attr.label_list(
            providers = [CcInfo],
            doc = "cc_library dependencies providing headers/includes.",
        ),
        "copts": attr.string_list(
            doc = "Per-target compile flags layered on the toolchain defaults.",
        ),
        "linkopts": attr.string_list(
            doc = "Additional linker flags (e.g. -static, -lstdc++, -lm).",
        ),
        "local_defines": attr.string_list(
            doc = "Preprocessor defines for this target only.",
        ),
        "includes": attr.string_list(
            doc = "Angle/quote include search paths (-I), package-relative.",
        ),
        "quote_includes": attr.string_list(
            doc = "Quote include search paths (-iquote), package-relative.",
        ),
        "freestanding": attr.bool(
            default = True,
            doc = "Keep the toolchain freestanding feature. Set False for a " +
                  "hosted binary that links the standard runtime.",
        ),
    },
    toolchains = use_cc_toolchain(),
    fragments = ["cpp"],
    executable = True,
)

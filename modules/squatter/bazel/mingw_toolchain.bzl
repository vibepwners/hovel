"""In-repo cc_toolchain over an extracted MinGW-w64 tarball.

This is a corrected MinGW cc_toolchain helper. The upstream helper this started
from wired compiler/linker tool groups but omitted `ar_files`, so the archive
action that backs *every* cc_library could not find the archiver in the sandbox
("execvp(...-ar): No such file or directory"). That makes cc_library -- and
therefore cc_test, googletest, nanopb, and anything else that vendors a static
library -- unbuildable.

The fix is small and surgical: the same toolchain, plus `ar_files`, plus a
`-lstdc++` on the C++ link (the gcc driver, unlike g++, does not pull libstdc++
on its own; harmless for pure-C links, which never reference it). Everything
else mirrors upstream so behaviour for the existing C binaries is unchanged.
"""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load(
    "@rules_cc//cc:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
)
load("@rules_cc//cc:defs.bzl", "CcToolchainConfigInfo", "cc_common", "cc_toolchain")

_LINK_ACTIONS = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

_COMPILE_ACTIONS = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
]

def _config_impl(ctx):
    tools = ctx.attr.target + "-"
    tool_paths = [
        tool_path(name = "gcc", path = "bin/%sgcc" % tools),
        tool_path(name = "cpp", path = "bin/%scpp" % tools),
        tool_path(name = "ar", path = "bin/%sar" % tools),
        tool_path(name = "gcov", path = "bin/%sgcov" % tools),
        tool_path(name = "ld", path = "bin/%sld" % tools),
        tool_path(name = "nm", path = "bin/%snm" % tools),
        tool_path(name = "objdump", path = "bin/%sobjdump" % tools),
        tool_path(name = "strip", path = "bin/%sstrip" % tools),
    ]

    features = [
        feature(
            name = "path_normalization",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = _COMPILE_ACTIONS,
                    flag_groups = [flag_group(flags = [
                        "-no-canonical-prefixes",
                        "-fno-canonical-system-headers",
                    ])],
                ),
                flag_set(
                    actions = _LINK_ACTIONS,
                    flag_groups = [flag_group(flags = ["-no-canonical-prefixes"])],
                ),
            ],
        ),
    ]
    if ctx.attr.static_runtime:
        features.append(feature(
            name = "static_runtime",
            enabled = True,
            flag_sets = [flag_set(
                actions = _LINK_ACTIONS,
                flag_groups = [flag_group(flags = [
                    "-static-libgcc",
                    "-static-libstdc++",
                    "-static",
                    "-Wl,-Bstatic,--whole-archive",
                    "-lwinpthread",
                    "-Wl,--no-whole-archive",
                    # The gcc driver (not g++) must be told to link the C++
                    # runtime, and it MUST stay under -Bstatic so libstdc++ is
                    # linked statically (otherwise the .exe imports
                    # libstdc++-6.dll and won't load). A pure-C link pulls
                    # nothing from the archive. Switch back to dynamic last, for
                    # the system import libs (ws2_32, etc.).
                    "-lstdc++",
                    "-Wl,-Bdynamic",
                ])],
            )],
        ))

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "mingw-%s" % ctx.attr.target,
        host_system_name = "x86_64-linux-gnu",
        target_system_name = ctx.attr.target,
        target_cpu = ctx.attr.cpu,
        target_libc = "ucrt",
        compiler = "gcc",
        abi_version = ctx.attr.target,
        abi_libc_version = "ucrt",
        tool_paths = tool_paths,
        features = features,
        cxx_builtin_include_directories = ctx.attr.builtin_include_dirs,
    )

mingw_cc_toolchain_config = rule(
    implementation = _config_impl,
    attrs = {
        "target": attr.string(mandatory = True),
        "cpu": attr.string(mandatory = True),
        "static_runtime": attr.bool(default = True),
        "builtin_include_dirs": attr.string_list(default = []),
    },
    provides = [CcToolchainConfigInfo],
)

def mingw_cc_toolchain(name, target, cpu, static_runtime = True, builtin_include_dirs = []):
    """Define a cc_toolchain (+ registration target) over the extracted tarball.

    Args:
      name: Base name for the filegroup, config, cc_toolchain, and toolchain targets.
      target: MinGW toolchain target triple.
      cpu: Bazel CPU constraint suffix for the Windows target.
      static_runtime: Whether to link the GCC/C++ runtime statically.
      builtin_include_dirs: Built-in include directories reported by the toolchain.
    """
    native.filegroup(
        name = "%s_all" % name,
        srcs = native.glob(["**"], allow_empty = False),
    )

    mingw_cc_toolchain_config(
        name = "%s_config" % name,
        target = target,
        cpu = cpu,
        static_runtime = static_runtime,
        builtin_include_dirs = builtin_include_dirs,
    )

    cc_toolchain(
        name = "%s_cc" % name,
        toolchain_config = ":%s_config" % name,
        all_files = ":%s_all" % name,
        ar_files = ":%s_all" % name,  # <-- the fix: the archiver must be staged
        compiler_files = ":%s_all" % name,
        linker_files = ":%s_all" % name,
        dwp_files = ":%s_all" % name,
        objcopy_files = ":%s_all" % name,
        strip_files = ":%s_all" % name,
        supports_param_files = 1,
    )

    os_constraint = "@platforms//os:windows"
    cpu_constraint = "@platforms//cpu:x86_64" if cpu == "x86_64" else "@platforms//cpu:x86_32"

    native.toolchain(
        name = name,
        toolchain = ":%s_cc" % name,
        toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
        target_compatible_with = [os_constraint, cpu_constraint],
        visibility = ["//visibility:public"],
    )

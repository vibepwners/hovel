"""Module extension for fetching the ARM GNU bare-metal toolchain.

Downloads arm-none-eabi-gcc from developer.arm.com and registers it
as a Bazel CC toolchain for Cortex-M targets. Used to build PIC blobs
in hosted mode for Mbed OS.
"""

_TRIPLE = "arm-none-eabi"

_CONFIG_BZL_CONTENT = """\
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load(
    "@rules_cc//cc:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
)
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load(
    "@rules_cc//cc/toolchains:cc_toolchain_config_info.bzl",
    "CcToolchainConfigInfo",
)

_ALL_COMPILE_ACTIONS = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
]

_ALL_LINK_ACTIONS = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _config_impl(ctx):
    tool_paths = [
        tool_path(name = "gcc", path = "bin/{triple}-gcc"),
        tool_path(name = "g++", path = "bin/{triple}-g++"),
        tool_path(name = "ld", path = "bin/{triple}-ld"),
        tool_path(name = "ar", path = "bin/{triple}-ar"),
        tool_path(name = "nm", path = "bin/{triple}-nm"),
        tool_path(name = "objcopy", path = "bin/{triple}-objcopy"),
        tool_path(name = "objdump", path = "bin/{triple}-objdump"),
        tool_path(name = "strip", path = "bin/{triple}-strip"),
        tool_path(name = "as", path = "bin/{triple}-as"),
        tool_path(name = "cpp", path = "bin/{triple}-cpp"),
        tool_path(name = "gcov", path = "bin/{triple}-gcov"),
        # DWP is unused by this workspace. Point at a declared toolchain
        # binary rather than an undeclared host /usr/bin path.
        tool_path(name = "dwp", path = "bin/{triple}-gcc"),
    ]

    freestanding_feature = feature(
        name = "freestanding",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-ffreestanding",
                            "-fno-builtin",
                            "-fno-stack-protector",
                            "-fPIC",
                            "-ffunction-sections",
                            "-fdata-sections",
                            "-Os",
                            "-Wall",
                            "-Werror",
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = _ALL_LINK_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-nostdlib",
                            "-nostartfiles",
                            "-Wl,--gc-sections",
                        ],
                    ),
                ],
            ),
        ],
    )

    arch_flags_feature = feature(
        name = "arch_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = {extra_cflags},
                    ),
                ],
            ),
        ],
    )

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "{toolchain_id}",
        host_system_name = "x86_64-linux-gnu",
        target_system_name = "{triple}",
        target_cpu = "cortex-m4",
        target_libc = "none",
        compiler = "gcc",
        abi_version = "gcc",
        abi_libc_version = "none",
        tool_paths = tool_paths,
        features = [freestanding_feature, arch_flags_feature],
    )

arm_none_eabi_config = rule(
    implementation = _config_impl,
    attrs = {{}},
    provides = [CcToolchainConfigInfo],
)
"""

_BUILD_FILE_CONTENT = """\
load("@rules_cc//cc:defs.bzl", "cc_toolchain")
load(":config.bzl", "arm_none_eabi_config")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_files",
    srcs = glob([
        "bin/{triple}-*",
        "lib/gcc/{triple}/**",
        "libexec/gcc/{triple}/**",
        "{triple}/include/**",
        "{triple}/lib/**",
    ]),
)

filegroup(
    name = "compiler_files",
    srcs = glob([
        "bin/{triple}-*",
        "lib/gcc/{triple}/**",
        "libexec/gcc/{triple}/**",
        "{triple}/include/**",
    ]),
)

filegroup(
    name = "linker_files",
    srcs = glob([
        "bin/{triple}-*",
        "lib/gcc/{triple}/**",
        "libexec/gcc/{triple}/**",
        "{triple}/lib/**",
    ]),
)

filegroup(
    name = "ar_files",
    srcs = glob(["bin/{triple}-ar"]),
)

filegroup(
    name = "objcopy_files",
    srcs = glob(["bin/{triple}-objcopy"]),
)

filegroup(
    name = "strip_files",
    srcs = glob(["bin/{triple}-strip"]),
)

filegroup(
    name = "dwp_files",
    srcs = glob(["bin/{triple}-gcc"]),
)

filegroup(
    name = "readelf_files",
    srcs = glob(["bin/{triple}-readelf"]),
)

arm_none_eabi_config(name = "toolchain_config")

cc_toolchain(
    name = "cc_toolchain",
    toolchain_config = ":toolchain_config",
    all_files = ":all_files",
    compiler_files = ":compiler_files",
    linker_files = ":linker_files",
    ar_files = ":ar_files",
    objcopy_files = ":objcopy_files",
    strip_files = ":strip_files",
    dwp_files = ":dwp_files",
)
"""

def _arm_none_eabi_repo_impl(ctx):
    """Repository rule that fetches the ARM GNU bare-metal toolchain."""
    url = ctx.attr.url
    sha256 = ctx.attr.sha256
    strip_prefix = ctx.attr.strip_prefix
    extra_cflags = ctx.attr.extra_cflags

    download_kwargs = {
        "url": [url],
    }
    if strip_prefix:
        download_kwargs["stripPrefix"] = strip_prefix
    if sha256:
        download_kwargs["sha256"] = sha256
    elif ctx.os.environ.get("PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS"):
        # buildifier: disable=print
        print("WARNING: arm-none-eabi toolchain has no SHA256 pin.")
    else:
        fail(
            "arm-none-eabi toolchain has no SHA256 pin. " +
            "Set sha256 in MODULE.bazel or " +
            "run with PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS=1",
        )

    result = ctx.download_and_extract(**download_kwargs)

    if not sha256 and hasattr(result, "sha256"):
        # buildifier: disable=print
        print("  Pin with: sha256 = \"{}\"".format(result.sha256))

    config_bzl = _CONFIG_BZL_CONTENT.format(
        triple = _TRIPLE,
        extra_cflags = repr(extra_cflags),
        toolchain_id = "arm_none_eabi",
    )
    ctx.file("config.bzl", config_bzl)

    build_content = _BUILD_FILE_CONTENT.format(triple = _TRIPLE)
    ctx.file("BUILD.bazel", build_content)

arm_none_eabi_repo = repository_rule(
    implementation = _arm_none_eabi_repo_impl,
    attrs = {
        "url": attr.string(mandatory = True),
        "strip_prefix": attr.string(default = ""),
        "sha256": attr.string(default = ""),
        "extra_cflags": attr.string_list(default = []),
    },
    environ = ["PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS"],
)

# --- Module extension ---

_TOOLCHAIN_TAG = tag_class(
    attrs = {
        "url": attr.string(mandatory = True),
        "strip_prefix": attr.string(default = ""),
        "sha256": attr.string(default = ""),
        "extra_cflags": attr.string_list(default = []),
    },
)

def _arm_none_eabi_impl(module_ctx):
    for mod in module_ctx.modules:
        for tc in mod.tags.toolchain:
            arm_none_eabi_repo(
                name = "arm_none_eabi",
                url = tc.url,
                strip_prefix = tc.strip_prefix,
                sha256 = tc.sha256,
                extra_cflags = tc.extra_cflags,
            )

arm_none_eabi = module_extension(
    implementation = _arm_none_eabi_impl,
    tag_classes = {
        "toolchain": _TOOLCHAIN_TAG,
    },
)

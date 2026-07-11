"""Module extension for fetching Bootlin cross-compilation toolchains.

Each toolchain archive is downloaded from toolchains.bootlin.com, extracted,
and registered as a Bazel CC toolchain. The cc_toolchain_config rule is
generated inside each external repo so tool_path references are repo-relative.
"""

_BOOTLIN_URL_TEMPLATE = (
    "https://toolchains.bootlin.com/downloads/releases/toolchains/" +
    "{arch}/tarballs/{arch}--{libc}--stable-{version}.tar.xz"
)

# The config rule definition goes in a .bzl file inside the external repo.
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
        # Bootlin's public compiler symlinks go through toolchain-wrapper,
        # which realpaths itself and injects an absolute --sysroot. Point at
        # the real drivers so depfiles stay exec-root-relative under Bazel.
        tool_path(name = "gcc", path = "bin/{triple}-gcc.br_real"),
        tool_path(name = "g++", path = "bin/{triple}-g++.br_real"),
        tool_path(name = "ld", path = "bin/{triple}-ld"),
        tool_path(name = "ar", path = "bin/{triple}-ar"),
        tool_path(name = "nm", path = "bin/{triple}-nm"),
        tool_path(name = "objcopy", path = "bin/{triple}-objcopy"),
        tool_path(name = "objdump", path = "bin/{triple}-objdump"),
        tool_path(name = "strip", path = "bin/{triple}-strip"),
        tool_path(name = "as", path = "bin/{triple}-as"),
        tool_path(name = "cpp", path = "bin/{triple}-cpp.br_real"),
        tool_path(name = "gcov", path = "bin/{triple}-gcov"),
        # DWP is unused by this workspace. Point at a declared toolchain
        # binary rather than an undeclared host /usr/bin path.
        tool_path(name = "dwp", path = "bin/{triple}-gcc.br_real"),
    ]

    path_normalization_feature = feature(
        name = "path_normalization",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-no-canonical-prefixes",
                            "-fno-canonical-system-headers",
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = _ALL_LINK_ACTIONS,
                flag_groups = [
                    flag_group(flags = ["-no-canonical-prefixes"]),
                ],
            ),
        ],
    )

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

    extra_cflags = {extra_cflags}
    arch_flags_feature = feature(
        name = "arch_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(flags = extra_cflags),
                ] if extra_cflags else [],
            ),
        ],
    ) if extra_cflags else None

    features = [path_normalization_feature, freestanding_feature]
    if arch_flags_feature:
        features.append(arch_flags_feature)

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "{toolchain_id}",
        host_system_name = "x86_64-linux-gnu",
        target_system_name = "{triple}",
        target_cpu = "{target_cpu}",
        target_libc = "{target_libc}",
        compiler = "gcc",
        abi_version = "gcc",
        abi_libc_version = "{target_libc}",
        tool_paths = tool_paths,
        features = features,
        # Paths to the toolchain's own headers. Bazel resolves %package(...)%
        # under the exec root, so the include whitelist works for local and
        # remote execution without baking in output-base paths.
        # Freestanding blobs never include system headers, so this is inert
        # for them.
        cxx_builtin_include_directories = {builtin_include_dirs},
    )

bootlin_config = rule(
    implementation = _config_impl,
    attrs = {{}},
    provides = [CcToolchainConfigInfo],
)
"""

_BOOTLIN_BUILD_FILE_CONTENT = """\
load("@rules_cc//cc:defs.bzl", "cc_toolchain")
load(":config.bzl", "bootlin_config")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_files",
    srcs = glob([
        "bin/{triple}-*",
        "bin/toolchain-wrapper",
        "lib/gcc/{triple}/**",
        "libexec/gcc/{triple}/**",
        "{triple}/bin/**",
        "{triple}/include/**",
        "{triple}/lib/**",
        "{triple}/sysroot/**",
    ]),
)

filegroup(
    name = "compiler_files",
    srcs = glob([
        "bin/{triple}-*",
        "bin/toolchain-wrapper",
        "lib/gcc/{triple}/**",
        "libexec/gcc/{triple}/**",
        "{triple}/bin/**",
        "{triple}/include/**",
        # Hosted compiles (C++ test runners) need the libc sysroot headers;
        # freestanding blobs don't, but globbing them is harmless.
        "{triple}/sysroot/**",
    ]),
)

filegroup(
    name = "linker_files",
    srcs = glob([
        "bin/{triple}-*",
        "bin/toolchain-wrapper",
        "lib/gcc/{triple}/**",
        "libexec/gcc/{triple}/**",
        "{triple}/bin/**",
        "{triple}/lib/**",
        # Hosted links need crt objects and libc/libstdc++ from the sysroot.
        "{triple}/sysroot/**",
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
    srcs = glob(["bin/{triple}-gcc.br_real"]),
)

filegroup(
    name = "readelf_files",
    srcs = glob(["bin/{triple}-readelf"]),
)

bootlin_config(name = "toolchain_config")

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

def _bootlin_toolchain_repo_impl(ctx):
    """Repository rule that fetches a single Bootlin toolchain archive."""
    arch = ctx.attr.arch
    version = ctx.attr.version
    triple = ctx.attr.triple
    libc = ctx.attr.libc
    sha256 = ctx.attr.sha256
    extra_cflags = ctx.attr.extra_cflags
    target_cpu = ctx.attr.target_cpu
    toolchain_id = ctx.attr.toolchain_id

    url = _BOOTLIN_URL_TEMPLATE.format(arch = arch, libc = libc, version = version)

    download_kwargs = {
        "url": [url],
        "stripPrefix": "{arch}--{libc}--stable-{version}".format(
            arch = arch,
            libc = libc,
            version = version,
        ),
    }
    if sha256:
        download_kwargs["sha256"] = sha256
    elif ctx.os.environ.get("PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS"):
        # buildifier: disable=print
        print("WARNING: Bootlin toolchain '{}' has no SHA256 pin. ".format(toolchain_id) +
              "Builds are not reproducible. Set sha256 in MODULE.bazel.")
    else:
        fail(
            "Bootlin toolchain '{}' has no SHA256 pin. ".format(toolchain_id) +
            "Unpinned toolchains are a supply-chain risk. Either:\n" +
            "  1. Run with PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS=1 to fetch and print the hash, or\n" +
            "  2. Set sha256 in MODULE.bazel after first fetch.",
        )

    result = ctx.download_and_extract(**download_kwargs)

    # Print the SHA256 for pinning if not already set.
    if not sha256 and hasattr(result, "sha256"):
        # buildifier: disable=print
        print("  Pin with: sha256 = \"{}\"".format(result.sha256))

    gcc_versions = [
        entry.basename
        for entry in ctx.path("lib/gcc/{}".format(triple)).readdir(watch = "no")
        if entry.is_dir
    ]
    if len(gcc_versions) != 1:
        fail("Bootlin toolchain '{}' has unexpected GCC versions: {}".format(
            toolchain_id,
            gcc_versions,
        ))
    gcc_version = gcc_versions[0]

    # Exec-root-stable versions of the compiler's builtin search roots, in the
    # order reported by `g++ -E -xc++ - -v`. They are listed as builtin include
    # dirs so hosted compiles pass Bazel's absolute-path hermeticity check.
    # Repository rules expose only their canonical name through ctx.name; the
    # package placeholder needs that name to remain valid from the exec root.
    builtin_include_prefix = "%package(@@{}//)%".format(ctx.name)  # buildifier: disable=canonical-repository
    builtin_include_dirs = [
        "{}/{}/include/c++/{}".format(builtin_include_prefix, triple, gcc_version),
        "{}/{}/include/c++/{}/{}".format(builtin_include_prefix, triple, gcc_version, triple),
        "{}/{}/include/c++/{}/backward".format(builtin_include_prefix, triple, gcc_version),
        "{}/lib/gcc/{}/{}/include".format(builtin_include_prefix, triple, gcc_version),
        "{}/lib/gcc/{}/{}/include-fixed".format(builtin_include_prefix, triple, gcc_version),
        "{}/{}/include".format(builtin_include_prefix, triple),
        "{}/{}/sysroot/usr/include".format(builtin_include_prefix, triple),
    ]

    # Generate the config.bzl with baked-in triple and flags.
    config_bzl = _CONFIG_BZL_CONTENT.format(
        triple = triple,
        extra_cflags = repr(extra_cflags),
        target_cpu = target_cpu,
        toolchain_id = toolchain_id,
        target_libc = libc,
        builtin_include_dirs = repr(builtin_include_dirs),
    )
    ctx.file("config.bzl", config_bzl)

    # Generate the BUILD.bazel.
    build_content = _BOOTLIN_BUILD_FILE_CONTENT.format(triple = triple)
    ctx.file("BUILD.bazel", build_content)

bootlin_toolchain_repo = repository_rule(
    implementation = _bootlin_toolchain_repo_impl,
    attrs = {
        "arch": attr.string(mandatory = True),
        "libc": attr.string(default = "glibc"),
        "version": attr.string(mandatory = True),
        "triple": attr.string(mandatory = True),
        "sha256": attr.string(default = ""),
        "extra_cflags": attr.string_list(default = []),
        "target_cpu": attr.string(mandatory = True),
        "toolchain_id": attr.string(mandatory = True),
    },
    environ = ["PICBLOBS_ALLOW_UNPINNED_TOOLCHAINS"],
)

# --- Module extension ---

_TOOLCHAIN_TAG = tag_class(
    attrs = {
        "name": attr.string(mandatory = True),
        "arch": attr.string(mandatory = True),
        "triple": attr.string(mandatory = True),
        "libc": attr.string(default = "glibc"),
        "version": attr.string(mandatory = True),
        "sha256": attr.string(default = ""),
        "extra_cflags": attr.string_list(default = []),
        "target_cpu": attr.string(default = ""),
    },
)

def _bootlin_impl(module_ctx):
    """Module extension implementation: creates one repo per toolchain."""
    for mod in module_ctx.modules:
        for toolchain in mod.tags.toolchain:
            repo_name = "bootlin_{}".format(toolchain.name)
            bootlin_toolchain_repo(
                name = repo_name,
                arch = toolchain.arch,
                version = toolchain.version,
                triple = toolchain.triple,
                libc = toolchain.libc,
                sha256 = toolchain.sha256,
                extra_cflags = toolchain.extra_cflags,
                target_cpu = toolchain.target_cpu if toolchain.target_cpu else toolchain.name,
                toolchain_id = repo_name,
            )

bootlin = module_extension(
    implementation = _bootlin_impl,
    tag_classes = {
        "toolchain": _TOOLCHAIN_TAG,
    },
)

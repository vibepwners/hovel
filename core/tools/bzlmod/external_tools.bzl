"""Pinned external tool repositories shared by Hovel module files."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

_GOLANGCI_LINT_BUILD = """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "golangci_lint_bin",
    srcs = ["golangci-lint"],
)
"""

_VHS_BUILD = """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "vhs_bin",
    srcs = ["vhs"],
)
"""

_FFMPEG_BUILD = """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "ffmpeg_bin",
    srcs = ["bin/ffmpeg"],
)
"""

_UV_BUILD = """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "uv_bin",
    srcs = ["uv"],
)
"""

_CHROME_BUILD = """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "chrome_bin",
    srcs = ["chrome-linux64/chrome"],
)

filegroup(
    name = "chrome_files",
    srcs = glob(["chrome-linux64/**"]),
)
"""

_LLVM_MINGW_BUILD = """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "aarch64_libs",
    srcs = glob(["aarch64-w64-mingw32/lib/*"]),
)

filegroup(
    name = "x86_64_libs",
    srcs = glob(["x86_64-w64-mingw32/lib/*"]),
)

filegroup(
    name = "compiler_rt_windows",
    srcs = glob(["lib/clang/*/lib/windows/*"]),
)

filegroup(
    name = "clang_tidy_bin",
    srcs = ["bin/clang-tidy"],
)

filegroup(
    name = "clang_tidy_runtime",
    srcs = glob([
        "lib/libLLVM.so*",
        "lib/libclang-cpp.so*",
    ]),
)

filegroup(
    name = "clang_tidy_files",
    srcs = [
        ":clang_tidy_bin",
        ":clang_tidy_runtime",
    ],
)
"""

_TOOLS = {
    "buildifier_linux_amd64": struct(
        rule = "http_file",
        attrs = {
            "downloaded_file_path": "buildifier",
            "executable": True,
            "sha256": "5474cc5128a74e806783d54081f581662c4be8ae65022f557e9281ed5dc88009",
            "urls": ["https://github.com/bazelbuild/buildtools/releases/download/v7.3.1/buildifier-linux-amd64"],
        },
    ),
    "buildifier_linux_arm64": struct(
        rule = "http_file",
        attrs = {
            "downloaded_file_path": "buildifier",
            "executable": True,
            "sha256": "0bf86c4bfffaf4f08eed77bde5b2082e4ae5039a11e2e8b03984c173c34a561c",
            "urls": ["https://github.com/bazelbuild/buildtools/releases/download/v7.3.1/buildifier-linux-arm64"],
        },
    ),
    "chrome_for_testing_linux_x86_64": struct(
        rule = "http_archive",
        attrs = {
            "build_file_content": _CHROME_BUILD,
            "sha256": "ad115a7498a17f53f6ed0914458326c6516addc756224db14c32184a9b1ab078",
            "strip_prefix": "",
            "urls": ["https://storage.googleapis.com/chrome-for-testing-public/150.0.7871.46/linux64/chrome-linux64.zip"],
        },
    ),
    "ffmpeg_linux_x86_64": struct(
        rule = "http_archive",
        attrs = {
            "build_file_content": _FFMPEG_BUILD,
            "sha256": "7aadf7d95d94e9dc71d4283d64be209ef1ba4cab5eb09893c29037223704d0b1",
            "strip_prefix": "ffmpeg-n8.1.2-21-gce3c09c101-linux64-gpl-8.1",
            "urls": ["https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-07-03-13-21/ffmpeg-n8.1.2-21-gce3c09c101-linux64-gpl-8.1.tar.xz"],
        },
    ),
    "golangci_lint_linux_amd64": struct(
        rule = "http_archive",
        attrs = {
            "build_file_content": _GOLANGCI_LINT_BUILD,
            "sha256": "8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553",
            "strip_prefix": "golangci-lint-2.12.2-linux-amd64",
            "urls": ["https://github.com/golangci/golangci-lint/releases/download/v2.12.2/golangci-lint-2.12.2-linux-amd64.tar.gz"],
        },
    ),
    "llvm_mingw_ucrt_linux_x86_64": struct(
        rule = "http_archive",
        attrs = {
            "build_file_content": _LLVM_MINGW_BUILD,
            "sha256": "534b92e067b22a6b4441f48ae9240a3341b17825d04d577eab0cf85c44b4deda",
            "strip_prefix": "llvm-mingw-20260616-ucrt-ubuntu-22.04-x86_64",
            "urls": ["https://github.com/mstorsjo/llvm-mingw/releases/download/20260616/llvm-mingw-20260616-ucrt-ubuntu-22.04-x86_64.tar.xz"],
        },
    ),
    "ttyd_linux_x86_64": struct(
        rule = "http_file",
        attrs = {
            "downloaded_file_path": "ttyd",
            "executable": True,
            "sha256": "8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55",
            "urls": ["https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64"],
        },
    ),
    "uv_linux_x86_64": struct(
        rule = "http_archive",
        attrs = {
            "build_file_content": _UV_BUILD,
            "sha256": "6426a73c3837e6e2483ee344cbc00f36394d179afcba6183cb77437e67db4af0",
            "strip_prefix": "uv-x86_64-unknown-linux-gnu",
            "urls": ["https://github.com/astral-sh/uv/releases/download/0.11.26/uv-x86_64-unknown-linux-gnu.tar.gz"],
        },
    ),
    "vhs_linux_x86_64": struct(
        rule = "http_archive",
        attrs = {
            "build_file_content": _VHS_BUILD,
            "sha256": "99cb634587eaae0473c1ea377db80c3a048c27f99fe0a7febb1a1e8cb7ee5009",
            "strip_prefix": "vhs_0.11.0_Linux_x86_64",
            "urls": ["https://github.com/charmbracelet/vhs/releases/download/v0.11.0/vhs_0.11.0_Linux_x86_64.tar.gz"],
        },
    ),
}

_GROUPS = {
    "core": [
        "golangci_lint_linux_amd64",
        "llvm_mingw_ucrt_linux_x86_64",
    ],
    "docs": [
        "chrome_for_testing_linux_x86_64",
        "ffmpeg_linux_x86_64",
        "ttyd_linux_x86_64",
        "uv_linux_x86_64",
        "vhs_linux_x86_64",
    ],
    "picblobs": [
        "buildifier_linux_amd64",
        "buildifier_linux_arm64",
    ],
}

_GROUP_TAG = tag_class(attrs = {"name": attr.string(mandatory = True)})

_TOOL_TAG = tag_class(attrs = {"name": attr.string(mandatory = True)})

def _external_tools_impl(module_ctx):
    requested = {}
    for mod in module_ctx.modules:
        for group in mod.tags.group:
            if group.name not in _GROUPS:
                fail("unknown external tool group '{}'; known groups: {}".format(
                    group.name,
                    ", ".join(sorted(_GROUPS.keys())),
                ))
            for tool in _GROUPS[group.name]:
                requested[tool] = True
        for tool in mod.tags.tool:
            if tool.name not in _TOOLS:
                fail("unknown external tool '{}'; known tools: {}".format(
                    tool.name,
                    ", ".join(sorted(_TOOLS.keys())),
                ))
            requested[tool.name] = True

    for name in sorted(requested.keys()):
        tool = _TOOLS[name]
        attrs = dict(tool.attrs)
        attrs["name"] = name
        if tool.rule == "http_archive":
            http_archive(**attrs)
        elif tool.rule == "http_file":
            http_file(**attrs)
        else:
            fail("unknown repository rule '{}' for external tool '{}'".format(tool.rule, name))

external_tools = module_extension(
    implementation = _external_tools_impl,
    tag_classes = {
        "group": _GROUP_TAG,
        "tool": _TOOL_TAG,
    },
)

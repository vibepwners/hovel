load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

MINGW_W64_I686_REPO = "mingw_w64_i686"

def _windows_toolchains_impl(module_ctx):
    http_archive(
        name = MINGW_W64_I686_REPO,
        build_file_content = """
package(default_visibility = ["//visibility:public"])

exports_files(glob(["**/*"]))
""",
        sha256 = "2eb51859f539890133f5d0419b1bd534fb7fb8b522018de838ff1f5c09abf3c2",
        strip_prefix = "mingw-w64-gcc-15.2.0-ucrt-posix-dw2-i686-w64-mingw32-linux-x86_64",
        urls = [
            "https://github.com/Vibe-Pwners/windows-toolchains/releases/download/v0.0.1/mingw-w64-gcc-15.2.0-ucrt-posix-dw2-i686-w64-mingw32-linux-x86_64.tar.xz",
        ],
    )

windows_toolchains = module_extension(
    implementation = _windows_toolchains_impl,
)

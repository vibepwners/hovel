"""Module extension for hermetic QEMU user-mode interpreters.

The picblobs Bazel tests need concrete ``qemu-*-static`` binaries during
analysis so they can declare the interpreter in ``data``. Fetching a pinned
distro ``qemu-user-static`` package keeps CI independent from host packages
while still exposing the same multi-architecture interpreter set that
picblobs supports at runtime.
"""

# Debian 12 is intentional: it is the newest stable package that still ships
# the complete legacy interpreter set below. Newer Debian releases use a
# transitional package that omits several architectures Picblobs supports.
_QEMU_USER_STATIC_URLS = [
    "https://deb.debian.org/debian/pool/main/q/qemu/qemu-user-static_7.2+dfsg-7+deb12u18+b3_amd64.deb",
]

_QEMU_USER_STATIC_SHA256 = "c3e3ba2bd87f8c5b9a5da5ef21b5a3b82d7c63b89dd448d9ddaa4eabc5b6e402"

_QEMU_USER_STATIC_BINARIES = [
    "qemu-aarch64-static",
    "qemu-arm-static",
    "qemu-i386-static",
    "qemu-mips-static",
    "qemu-mipsel-static",
    "qemu-ppc-static",
    "qemu-ppc64le-static",
    "qemu-riscv64-static",
    "qemu-s390x-static",
    "qemu-sparc-static",
    "qemu-x86_64-static",
]

def _build_file():
    lines = [
        'package(default_visibility = ["//visibility:public"])',
        "",
        "filegroup(",
        '    name = "all",',
        "    srcs = [",
    ]
    lines.extend(['        "bin/{}",'.format(binary) for binary in _QEMU_USER_STATIC_BINARIES])
    lines.extend([
        "    ],",
        ")",
        "",
        "alias(",
        '    name = "qemu",',
        '    actual = ":qemu-arm-static",',
        ")",
        "",
    ])

    for binary in _QEMU_USER_STATIC_BINARIES:
        lines.extend([
            "filegroup(",
            '    name = "{}",'.format(binary),
            '    srcs = ["bin/{}"],'.format(binary),
            ")",
            "",
        ])

    return "\n".join(lines)

def _qemu_user_static_repo_impl(ctx):
    ctx.download_and_extract(
        url = ctx.attr.urls,
        output = "deb",
        sha256 = ctx.attr.sha256,
        type = "deb",
    )
    ctx.extract(
        archive = "deb/data.tar.xz",
        output = "pkg",
    )

    for binary in _QEMU_USER_STATIC_BINARIES:
        source = ctx.path("pkg/usr/bin/{}".format(binary))
        if not source.exists:
            fail("qemu-user-static package did not contain usr/bin/{}".format(binary))
        ctx.symlink(source, "bin/{}".format(binary))

    ctx.file("BUILD.bazel", _build_file())

qemu_user_static_repo = repository_rule(
    implementation = _qemu_user_static_repo_impl,
    attrs = {
        "sha256": attr.string(default = _QEMU_USER_STATIC_SHA256),
        "urls": attr.string_list(default = _QEMU_USER_STATIC_URLS),
    },
)

def _qemu_arm_alias_repo_impl(ctx):
    ctx.file("BUILD.bazel", """\
package(default_visibility = ["//visibility:public"])

alias(
    name = "qemu",
    actual = "@qemu_user_static//:qemu-arm-static",
)
""")

qemu_arm_repo = repository_rule(
    implementation = _qemu_arm_alias_repo_impl,
)

def _qemu_impl(_module_ctx):
    qemu_user_static_repo(name = "qemu_user_static")
    qemu_arm_repo(name = "qemu_arm_static")

qemu = module_extension(
    implementation = _qemu_impl,
)

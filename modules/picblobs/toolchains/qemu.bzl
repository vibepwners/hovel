"""Module extension for locating a host qemu-arm interpreter.

QEMU user-mode is a system prerequisite (like a kernel). This extension
wraps the host binary into a Bazel-visible label so tests can declare it as
a dependency.

It accepts either the static build (``qemu-arm-static``) or the
dynamically-linked ``qemu-arm`` shipped by the ``qemu-user`` package, which
is what newer distros (e.g. Ubuntu 26.04, paired with ``qemu-user-binfmt``)
provide. This mirrors ``find_qemu`` on the Python side.
"""

# Searched in order; the static name wins when both are present.
_QEMU_ARM_CANDIDATES = ["qemu-arm-static", "qemu-arm"]

def _qemu_repo_impl(ctx):
    qemu = None
    for name in _QEMU_ARM_CANDIDATES:
        found = ctx.which(name)
        if found:
            qemu = found
            break

    if not qemu:
        fail(
            "No qemu-arm interpreter found on PATH (looked for {}). ".format(
                ", ".join(_QEMU_ARM_CANDIDATES),
            ) +
            "Install qemu-user-static, or qemu-user + qemu-user-binfmt.",
        )

    ctx.symlink(qemu, "qemu-bin")
    ctx.file("BUILD.bazel", """\
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "qemu",
    srcs = ["qemu-bin"],
)
""")

qemu_arm_repo = repository_rule(
    implementation = _qemu_repo_impl,
    local = True,
)

def _qemu_impl(_module_ctx):
    qemu_arm_repo(name = "qemu_arm_static")

qemu = module_extension(
    implementation = _qemu_impl,
)

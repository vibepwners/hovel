"""C linting and formatting checks for Bazel.

Provides:
  1. clang_tidy_aspect   — runs clang-tidy on cc_library/cc_binary targets
  2. cppcheck_test       — runs cppcheck as a Bazel test

Usage:
  # Run clang-tidy on all C targets:
  bazel build --config=picblobs_lint //modules/picblobs/src/... //modules/picblobs/tests/...

  # Run cppcheck:
  bazel test //modules/picblobs/src:cppcheck
"""

load("@picblobs_pip//:requirements.bzl", "requirement")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_python//python:defs.bzl", "py_test")

# ============================================================
# clang-tidy aspect
# ============================================================

# Compile flags clang-tidy uses to parse C sources. Mirrors the toolchain
# `freestanding` feature compile flag_set (see toolchains/bootlin.bzl).
# clang-tidy is a separate binary from gcc and won't pick these up from
# the toolchain, so they're forwarded explicitly.
_CLANG_TIDY_COMPILE_FLAGS = [
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fPIC",
    "-ffunction-sections",
    "-fdata-sections",
    "-Os",
    "-Wall",
]

def _clang_tidy_aspect_impl(target, ctx):
    """Aspect that runs clang-tidy on C source files.

    Fails the build if clang-tidy reports any warnings or errors.
    """
    if CcInfo not in target:
        return []

    srcs = []
    if hasattr(ctx.rule.attr, "srcs"):
        for src in ctx.rule.attr.srcs:
            for f in src.files.to_list():
                if f.extension == "c":
                    srcs.append(f)

    if not srcs:
        return [OutputGroupInfo(lint_results = depset())]

    compilation_context = target[CcInfo].compilation_context
    header_inputs = compilation_context.headers.to_list()

    # Stage .clang-tidy into the action and point clang-tidy at it explicitly.
    # Without this, sandboxed actions can't find the config by directory walk,
    # so clang-tidy silently runs with no project checks (e.g. the Barr-C
    # readability-braces-around-statements rule never fires).
    config_file = ctx.file._clang_tidy_config

    outputs = []
    for src in srcs:
        lint_output = ctx.actions.declare_file(
            "{}.clang-tidy.txt".format(src.short_path),
        )
        outputs.append(lint_output)

        args = ctx.actions.args()
        args.add("--clang-tidy", ctx.file._clang_tidy)
        args.add("--output", lint_output)
        args.add("--")
        args.add("--quiet")
        args.add("--warnings-as-errors=*")
        args.add(src)
        args.add(config_file, format = "--config-file=%s")
        args.add("--")
        args.add_all(compilation_context.includes, before_each = "-I")
        args.add_all(compilation_context.system_includes, before_each = "-isystem")
        args.add_all(compilation_context.quote_includes, before_each = "-iquote")
        args.add_all(_CLANG_TIDY_COMPILE_FLAGS)

        ctx.actions.run(
            executable = ctx.executable._clang_tidy_runner,
            outputs = [lint_output],
            inputs = [src, config_file] + header_inputs,
            arguments = [args],
            tools = depset(
                [ctx.executable._clang_tidy_runner, ctx.file._clang_tidy],
                transitive = [
                    ctx.attr._clang_tidy_runner[DefaultInfo].files,
                    ctx.attr._clang_tidy_runner[DefaultInfo].default_runfiles.files,
                    ctx.attr._clang_tidy_runner[DefaultInfo].data_runfiles.files,
                ],
            ),
            mnemonic = "ClangTidy",
            progress_message = "clang-tidy %{label}: " + src.short_path,
        )

    return [OutputGroupInfo(lint_results = depset(outputs))]

clang_tidy_aspect = aspect(
    implementation = _clang_tidy_aspect_impl,
    attr_aspects = ["deps"],
    attrs = {
        "_clang_tidy_config": attr.label(
            default = Label("//modules/picblobs:.clang-tidy"),
            allow_single_file = True,
        ),
        "_clang_tidy": attr.label(
            default = Label("@llvm_mingw_ucrt_linux_x86_64//:clang_tidy_bin"),
            allow_single_file = True,
            cfg = "exec",
        ),
        "_clang_tidy_runner": attr.label(
            default = Label("//modules/picblobs/tools:run_clang_tidy"),
            executable = True,
            cfg = "exec",
        ),
    },
    doc = "Runs clang-tidy on C source files. Fails on warnings.",
)

# ============================================================
# cppcheck test macro
# ============================================================

def cppcheck_test(name, srcs, include_dirs = ["src/include"], size = None, tags = None, **kwargs):
    """Runs cppcheck as a Bazel py_test with declared sources."""

    py_test(
        name = name,
        size = size,
        srcs = ["//modules/picblobs/tools:run_cppcheck_test.py"],
        main = "run_cppcheck_test.py",
        args = (
            ["--include-dir=" + include_dir for include_dir in include_dirs] +
            ["$(rootpath {})".format(src) for src in srcs]
        ),
        data = srcs,
        python_version = "PY3",
        tags = tags,
        deps = [requirement("cppcheck")],
        **kwargs
    )

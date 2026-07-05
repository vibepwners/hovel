"""C linting and formatting checks for Bazel.

Provides:
  1. clang_tidy_aspect   — runs clang-tidy on cc_library/cc_binary targets
  2. clang_format_test   — verifies C files are formatted per .clang-format
  3. cppcheck_test       — runs cppcheck as a Bazel test

Usage:
  # Run clang-tidy on all C targets:
  bazel build --config=picblobs_lint //modules/picblobs/src/... //modules/picblobs/tests/...

  # Check formatting:
  bazel test //modules/picblobs/src:format_check

  # Run cppcheck:
  bazel test //modules/picblobs/src:cppcheck
"""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

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

    Fails the build if clang-tidy reports any warnings or errors. When
    clang-tidy is missing on PATH the action skips silently unless
    PICBLOBS_REQUIRE_LINT_TOOLS=1 is set (CI sets this).
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
        args.add(lint_output)
        args.add(src)
        args.add(config_file, format = "--config-file=%s")
        args.add("--")
        args.add_all(compilation_context.includes, before_each = "-I")
        args.add_all(compilation_context.system_includes, before_each = "-isystem")
        args.add_all(compilation_context.quote_includes, before_each = "-iquote")
        args.add_all(_CLANG_TIDY_COMPILE_FLAGS)

        ctx.actions.run_shell(
            outputs = [lint_output],
            inputs = [src, config_file] + header_inputs,
            command = """
                set -eu
                out="$1"; shift
                if ! command -v clang-tidy >/dev/null 2>&1; then
                    if [ -n "${PICBLOBS_REQUIRE_LINT_TOOLS:-}" ]; then
                        echo "ERROR: clang-tidy not found but PICBLOBS_REQUIRE_LINT_TOOLS is set" >&2
                        exit 1
                    fi
                    echo "SKIP: clang-tidy not found" > "$out"
                    exit 0
                fi
                if ! clang-tidy --quiet --warnings-as-errors='*' "$@" > "$out" 2>&1; then
                    cat "$out" >&2
                    exit 1
                fi
            """,
            arguments = [args],
            use_default_shell_env = True,
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
    },
    doc = "Runs clang-tidy on C source files. Fails on warnings.",
)

# ============================================================
# clang-format check test
# ============================================================

def _clang_format_test_impl(ctx):
    """Test rule that verifies C files are formatted per .clang-format."""
    srcs = []
    for src in ctx.attr.srcs:
        srcs.extend(src.files.to_list())

    config = ctx.file.config

    script = ctx.actions.declare_file(ctx.attr.name + "_format_check.sh")

    src_paths = " ".join([f.short_path for f in srcs])

    ctx.actions.write(
        output = script,
        content = """\
#!/bin/bash
set -euo pipefail

if ! command -v clang-format >/dev/null 2>&1; then
    if [ -n "${{PICBLOBS_REQUIRE_LINT_TOOLS:-}}" ]; then
        echo "ERROR: clang-format not found but PICBLOBS_REQUIRE_LINT_TOOLS is set" >&2
        exit 1
    fi
    echo "SKIP: clang-format not found"
    exit 0
fi

failed=0
for f in {srcs}; do
    if ! clang-format --dry-run --Werror --style=file:{config} "$f" 2>/dev/null; then
        echo "FAIL: $f"
        failed=1
    fi
done

if [ $failed -ne 0 ]; then
    echo ""
    echo "Run: python tools/fmt.py"
    exit 1
fi

echo "{count} files formatted correctly"
""".format(
            srcs = src_paths,
            config = config.short_path,
            count = len(srcs),
        ),
        is_executable = True,
    )

    runfiles = ctx.runfiles(files = srcs + [config])

    return [DefaultInfo(
        executable = script,
        runfiles = runfiles,
    )]

clang_format_test = rule(
    implementation = _clang_format_test_impl,
    test = True,
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
            allow_files = [".c", ".h"],
            doc = "C source and header files to check.",
        ),
        "config": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "The .clang-format config file.",
        ),
    },
    doc = "Verifies C files are formatted per .clang-format.",
)

# ============================================================
# cppcheck test rule
# ============================================================

def _cppcheck_test_impl(ctx):
    """Test rule that runs cppcheck on a set of source files."""
    srcs = []
    for src in ctx.attr.srcs:
        srcs.extend(src.files.to_list())

    include_dirs = ctx.attr.include_dirs
    cppcheck = ctx.executable._cppcheck

    script = ctx.actions.declare_file(ctx.attr.name + "_cppcheck.sh")

    include_paths = " ".join(['"{}"'.format(d) for d in include_dirs])
    src_paths = " ".join(['"{}"'.format(f.short_path) for f in srcs])
    cppcheck_path = cppcheck.short_path

    ctx.actions.write(
        output = script,
        content = """\
#!/bin/bash
set -euo pipefail

cppcheck="{cppcheck}"
runfiles_root="$PWD"
args=(
    --error-exitcode=1
    --enable=warning,performance,portability
    --suppress=missingIncludeSystem
    --suppress=normalCheckLevelMaxBranches
    --inline-suppr
    --language=c
    --std=c11
)

for include_dir in {include_paths}; do
    args+=("-I" "$runfiles_root/$include_dir")
done
for src in {srcs}; do
    args+=("$runfiles_root/$src")
done

exec "$cppcheck" "${{args[@]}}"
""".format(cppcheck = cppcheck_path, include_paths = include_paths, srcs = src_paths),
        is_executable = True,
    )

    runfiles = ctx.runfiles(files = srcs + [cppcheck]).merge(ctx.attr._cppcheck[DefaultInfo].default_runfiles)

    return [DefaultInfo(
        executable = script,
        runfiles = runfiles,
    )]

cppcheck_test = rule(
    implementation = _cppcheck_test_impl,
    test = True,
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
            allow_files = [".c", ".h"],
            doc = "C source and header files to check.",
        ),
        "include_dirs": attr.string_list(
            default = ["src/include"],
            doc = "Include directories for cppcheck.",
        ),
        "_cppcheck": attr.label(
            default = Label("@cppcheck_linux_x86_64//:cppcheck"),
            executable = True,
            cfg = "exec",
            doc = "Hermetic cppcheck executable.",
        ),
    },
    doc = "Runs cppcheck as a Bazel test.",
)

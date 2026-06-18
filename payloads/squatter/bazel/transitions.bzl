"""windows_multiplatform: build one cc_binary for both Windows ABIs at once.

Bazel keys its output directory off the *configuration*, and a bare
`--platforms` change does not, on its own, alter that directory name (it is
historically derived from `--cpu`, which platform selection leaves at the host
value). Two `--platforms` builds of the same target therefore land on the same
output path and clobber each other.

This rule sidesteps that with a split transition that sets, per branch, both the
target platform *and* a distinct `--platform_suffix` (which does feed the output
directory). The two builds get separate output trees and coexist, and the rule
collects them under stable, ABI-named filenames:

    bazel build //payloads/squatter/windows/src:squatter_all
      -> squatter_all-x86_64.exe   (PE32+)
      -> squatter_all-i686.exe     (PE32)

The same suffixes are mirrored in //.bazelrc (--config=win64/--config=win32) so
a single-ABI build shares the very same configuration (and cache) as its branch
of this rule.
"""

# ABI key -> (target platform label, platform_suffix). Keep in lockstep with the
# --platform_suffix values in //.bazelrc.
_ABIS = {
    "x86_64": ("@windows_toolchains//platforms:windows_x64", "win-x64"),
    "i686": ("@windows_toolchains//platforms:windows_x86", "win-x86"),
}

def _split_impl(settings, attr):
    _ = (settings, attr)  # unused; the mapping is static
    return {
        abi: {
            "//command_line_option:platforms": [platform],
            "//command_line_option:platform_suffix": suffix,
        }
        for abi, (platform, suffix) in _ABIS.items()
    }

_per_abi = transition(
    implementation = _split_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platforms",
        "//command_line_option:platform_suffix",
    ],
)

def _multiplatform_impl(ctx):
    outputs = []
    for abi, target in ctx.split_attr.binary.items():
        produced = target[DefaultInfo].files.to_list()
        if len(produced) != 1:
            fail("expected exactly one output from binary for %s, got %d" %
                 (abi, len(produced)))
        out = ctx.actions.declare_file("{}-{}.exe".format(ctx.label.name, abi))
        ctx.actions.symlink(output = out, target_file = produced[0])
        outputs.append(out)
    return [DefaultInfo(files = depset(outputs))]

windows_multiplatform = rule(
    implementation = _multiplatform_impl,
    doc = "Build `binary` for every Windows ABI and gather the artifacts.",
    attrs = {
        "binary": attr.label(
            mandatory = True,
            cfg = _per_abi,
            doc = "The cc_binary to build once per ABI.",
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

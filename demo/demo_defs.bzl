"""Bazel rules for cacheable VHS demo rendering."""

STANDARD_DEMOS = [
    ("module-package-install-01-link", "tapes/module-package-install-01-link.tape"),
    ("mcp-agent-01-throw", "tapes/mcp-agent-01-throw.tape"),
    ("mock-survey-exploit-01-inspect", "tapes/mock-survey-exploit-01-inspect.tape"),
    ("mock-survey-exploit-02-throw", "tapes/mock-survey-exploit-02-throw.tape"),
    ("mock-survey-exploit-03-session-io", "tapes/mock-survey-exploit-03-session-io.tape"),
    ("mock-survey-exploit-04-session-connect", "tapes/mock-survey-exploit-04-session-connect.tape"),
    ("mock-survey-exploit-cli-02-session-io", "tapes/mock-survey-exploit-cli-02-session-io.tape"),
    ("mock-survey-exploit-cli-03-session-connect", "tapes/mock-survey-exploit-cli-03-session-connect.tape"),
    ("mock-survey-exploit-cli-commands-01-create", "tapes/mock-survey-exploit-cli-commands-01-create.tape"),
    ("mock-survey-exploit-cli-commands-02-config-before", "tapes/mock-survey-exploit-cli-commands-02-config-before.tape"),
    ("mock-survey-exploit-cli-commands-03-config-apply", "tapes/mock-survey-exploit-cli-commands-03-config-apply.tape"),
    ("mock-survey-exploit-cli-commands-04-save", "tapes/mock-survey-exploit-cli-commands-04-save.tape"),
    ("mock-survey-exploit-commands-01-create", "tapes/mock-survey-exploit-commands-01-create.tape"),
    ("mock-survey-exploit-commands-02-config-before", "tapes/mock-survey-exploit-commands-02-config-before.tape"),
    ("mock-survey-exploit-commands-03-config-apply", "tapes/mock-survey-exploit-commands-03-config-apply.tape"),
    ("mock-survey-exploit-commands-04-save", "tapes/mock-survey-exploit-commands-04-save.tape"),
]

def _vhs_demo(name, tape, wine = False):
    srcs = [
        tape,
        "chains/mock-survey-exploit.chain.yaml",
        "//:scripts/demo-step-setup.sh",
        "//:scripts/demo-mcp-agent-tmux.sh",
        "//tools/demo:check_gif_duration.py",
        "//tools/demo:vhs_version.txt",
    ]
    tools = [
        "//tools/demo:render_vhs_demo.sh",
        "//cmd/hovel:hovel",
        "//tools/demo/mcpagent:mcpagent",
        "//examples/go/mock_survey:mock_survey",
        "//examples/go/mock_exploit_session:mock_exploit_session",
    ]
    cmd = """
set -euo pipefail
$(execpath //tools/demo:render_vhs_demo.sh) \
  --tape "$(execpath :{tape})" \
  --tape-rel "demo/{tape}" \
  --output "$@" \
  --hovel-bin "$(execpath //cmd/hovel:hovel)" \
  --agent-bin "$(execpath //tools/demo/mcpagent:mcpagent)" \
  --mock-survey-go "$(execpath //examples/go/mock_survey:mock_survey)" \
  --mock-exploit-session-go "$(execpath //examples/go/mock_exploit_session:mock_exploit_session)" \
  --vhs-version-file "$(execpath //tools/demo:vhs_version.txt)"{wine_args}
""".format(
        tape = tape,
        wine_args = "" if not wine else """ \
  --squatter-provider "$(execpath //payloads/squatter/provider:squatter-provider)" \
  --squatter-exe "$(execpath //payloads/squatter/windows:squatter_x86_exe)" \
  --wine""",
    )
    if wine:
        srcs.extend([
            "//:tools/docker/squatter-wine/Dockerfile",
            "//:tools/docker/squatter-wine/entrypoint.sh",
            "//:tools/docker/squatter-wine/run.sh",
        ])
        tools.extend([
            "//payloads/squatter/provider:squatter-provider",
            "//payloads/squatter/windows:squatter_x86_exe",
        ])
    native.genrule(
        name = name + "_gif",
        srcs = srcs,
        outs = ["out/" + name + ".gif"],
        cmd = cmd,
        tags = ["manual"],
        tools = tools,
    )

def vhs_demo_targets():
    for name, tape in STANDARD_DEMOS:
        _vhs_demo(name, tape)

    _vhs_demo(
        "mcp-agent-02-squatter-wine",
        "tapes-docker/mcp-agent-02-squatter-wine.tape",
        wine = True,
    )

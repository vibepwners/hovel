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

UI_COMPONENT_DEMOS = [
    ("ui-command-table", "tapes/ui-command-table.tape"),
    ("ui-download-progress", "tapes/ui-download-progress.tape"),
    ("ui-logs", "tapes/ui-logs.tape"),
    ("ui-module-card", "tapes/ui-module-card.tape"),
    ("ui-status-panel", "tapes/ui-status-panel.tape"),
    ("ui-upload-progress", "tapes/ui-upload-progress.tape"),
]

def _runfiles_for(ctx, attr_name):
    target = getattr(ctx.attr, attr_name)
    executable = getattr(ctx.executable, attr_name)
    return [executable], [
        target[DefaultInfo].files,
        target[DefaultInfo].default_runfiles.files,
        target[DefaultInfo].data_runfiles.files,
    ]

def _vhs_demo_impl(ctx):
    out = ctx.actions.declare_file("out/" + ctx.attr.demo_name + ".gif")
    args = ctx.actions.args()
    args.add("--tape", ctx.file.tape)
    args.add("--tape-rel", "demo/" + ctx.attr.tape_rel)
    args.add("--output", out)
    args.add("--hovel-bin", ctx.executable.hovel)
    args.add("--agent-bin", ctx.executable.agent)
    args.add("--ui-catalog-bin", ctx.executable.ui_catalog)
    args.add("--mock-survey-go", ctx.executable.mock_survey_go)
    args.add("--mock-exploit-session-go", ctx.executable.mock_exploit_session_go)
    args.add("--chain-file", ctx.file.chain)
    args.add("--setup-script", ctx.file.setup_script)
    args.add("--tmux-script", ctx.file.tmux_script)
    args.add("--duration-checker", ctx.file.duration_checker)
    args.add("--vhs-bin", ctx.file._vhs)
    args.add("--vhs-version-file", ctx.file.vhs_version)
    args.add("--chrome-bin", ctx.file._chrome)
    args.add("--ffmpeg-bin", ctx.file._ffmpeg)
    args.add("--ttyd-bin", ctx.file._ttyd)

    inputs = [
        ctx.file.tape,
        ctx.file.chain,
        ctx.file.setup_script,
        ctx.file.tmux_script,
        ctx.file.duration_checker,
        ctx.file.vhs_version,
    ]
    tools = []
    transitive_tools = []
    for attr_name in ("runner", "hovel", "agent", "ui_catalog", "mock_survey_go", "mock_exploit_session_go"):
        files, transitive = _runfiles_for(ctx, attr_name)
        tools.extend(files)
        transitive_tools.extend(transitive)
    tools.append(ctx.file._vhs)
    tools.append(ctx.file._ffmpeg)
    tools.append(ctx.file._ttyd)
    tools.extend(ctx.files._chrome_files)

    if ctx.attr.wine:
        args.add("--wine")
        args.add("--squatter-provider", ctx.executable.squatter_provider)
        args.add("--squatter-exe", ctx.file.squatter_exe)
        args.add("--dockerfile", ctx.file.dockerfile)
        args.add("--docker-entrypoint", ctx.file.docker_entrypoint)
        args.add("--docker-runner", ctx.file.docker_runner)
        inputs.extend([ctx.file.squatter_exe, ctx.file.dockerfile, ctx.file.docker_entrypoint, ctx.file.docker_runner])
        files, transitive = _runfiles_for(ctx, "squatter_provider")
        tools.extend(files)
        transitive_tools.extend(transitive)

    ctx.actions.run(
        executable = ctx.executable.runner,
        arguments = [args],
        inputs = inputs,
        outputs = [out],
        tools = depset(tools, transitive = transitive_tools),
        mnemonic = "VhsDemo",
        progress_message = "Rendering VHS demo %{label}",
    )
    return [DefaultInfo(files = depset([out]))]

_vhs_demo_rule = rule(
    implementation = _vhs_demo_impl,
    attrs = {
        "agent": attr.label(executable = True, cfg = "exec", mandatory = True),
        "chain": attr.label(allow_single_file = True, mandatory = True),
        "demo_name": attr.string(mandatory = True),
        "docker_entrypoint": attr.label(allow_single_file = True),
        "docker_runner": attr.label(allow_single_file = True),
        "dockerfile": attr.label(allow_single_file = True),
        "duration_checker": attr.label(allow_single_file = True, mandatory = True),
        "hovel": attr.label(executable = True, cfg = "exec", mandatory = True),
        "mock_exploit_session_go": attr.label(executable = True, cfg = "exec", mandatory = True),
        "mock_survey_go": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runner": attr.label(
            default = "//docs/tools/demo:render_vhs_demo",
            executable = True,
            cfg = "exec",
        ),
        "setup_script": attr.label(allow_single_file = True, mandatory = True),
        "squatter_exe": attr.label(allow_single_file = True),
        "squatter_provider": attr.label(executable = True, cfg = "exec"),
        "tape": attr.label(allow_single_file = True, mandatory = True),
        "tape_rel": attr.string(mandatory = True),
        "tmux_script": attr.label(allow_single_file = True, mandatory = True),
        "ui_catalog": attr.label(executable = True, cfg = "exec", mandatory = True),
        "_vhs": attr.label(
            default = "@vhs_linux_x86_64//:vhs_bin",
            allow_single_file = True,
            cfg = "exec",
        ),
        "_chrome": attr.label(
            default = "@chrome_for_testing_linux_x86_64//:chrome_bin",
            allow_single_file = True,
            cfg = "exec",
        ),
        "_chrome_files": attr.label(
            default = "@chrome_for_testing_linux_x86_64//:chrome_files",
            cfg = "exec",
        ),
        "_ffmpeg": attr.label(
            default = "@ffmpeg_linux_x86_64//:ffmpeg_bin",
            allow_single_file = True,
            cfg = "exec",
        ),
        "_ttyd": attr.label(
            default = "@ttyd_linux_x86_64//file",
            allow_single_file = True,
            cfg = "exec",
        ),
        "vhs_version": attr.label(allow_single_file = True, mandatory = True),
        "wine": attr.bool(default = False),
    },
)

def _demo_manifest_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.name + ".txt")
    ctx.actions.write(out, "\n".join(ctx.attr.outputs) + "\n")
    return [DefaultInfo(files = depset([out]))]

demo_manifest = rule(
    implementation = _demo_manifest_impl,
    attrs = {
        "outputs": attr.string_list(mandatory = True),
    },
)

def _vhs_demo(name, tape, wine = False):
    kwargs = {}
    if wine:
        kwargs = {
            "docker_entrypoint": "//modules/docker/squatter-wine:entrypoint.sh",
            "docker_runner": "//modules/docker/squatter-wine:run.sh",
            "dockerfile": "//modules/docker/squatter-wine:Dockerfile",
            "squatter_exe": "//modules/squatter/windows:squatter_x86_exe",
            "squatter_provider": "//modules/squatter/provider:squatter-provider",
        }
    _vhs_demo_rule(
        name = name + "_gif",
        demo_name = name,
        tape = tape,
        tape_rel = tape,
        chain = "chains/mock-survey-exploit.chain.yaml",
        setup_script = "//:scripts/demo-step-setup.sh",
        tmux_script = "//:scripts/demo-mcp-agent-tmux.sh",
        duration_checker = "//docs/tools/demo:check_gif_duration.py",
        vhs_version = "//docs/tools/demo:vhs_version.txt",
        hovel = "@hovel_core//cmd/hovel:hovel",
        agent = "//docs/tools/demo/mcpagent:mcpagent",
        ui_catalog = "@hovel_core//cmd/hovel-ui-catalog:hovel-ui-catalog",
        mock_survey_go = "//modules/examples/go/mock_survey:mock_survey",
        mock_exploit_session_go = "//modules/examples/go/mock_exploit_session:mock_exploit_session",
        tags = ["manual"],
        wine = wine,
        **kwargs
    )

def vhs_demo_targets():
    for name, tape in STANDARD_DEMOS:
        _vhs_demo(name, tape)

    for name, tape in UI_COMPONENT_DEMOS:
        _vhs_demo(name, tape)

    _vhs_demo(
        "mcp-agent-02-squatter-wine",
        "tapes-docker/mcp-agent-02-squatter-wine.tape",
        wine = True,
    )

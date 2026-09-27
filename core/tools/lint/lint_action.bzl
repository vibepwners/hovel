"""Declared lint actions shared by verification and report materialization."""

load("@rules_python//python:defs.bzl", "py_test")

def _source_name(file, prefix):
    path = file.short_path
    if path.startswith("../"):
        pieces = path.split("/")
        return (prefix or "core/") + "/".join(pieces[2:])
    return prefix + path

def _impl(ctx):
    sources = []
    mapping = {}
    for file in ctx.files.srcs:
        name = _source_name(file, ctx.attr.source_prefix)
        if ctx.attr.prefixes and not any([name.startswith(p) for p in ctx.attr.prefixes]):
            continue
        if ctx.attr.suffixes and not any([name.endswith(s) for s in ctx.attr.suffixes]):
            continue
        mapping[name] = file.path
        sources.append(file)
    if not sources:
        fail("Lint source declaration is empty: " + ctx.attr.lint_id)
    spec = ctx.actions.declare_file(ctx.label.name + ".spec.json")
    result = ctx.actions.declare_directory(ctx.label.name + ".result")
    tools = [target[DefaultInfo].files_to_run for target in ctx.attr.tools]
    expansions = ctx.attr.tools + ctx.attr.data
    arguments = [ctx.expand_location(arg, targets = expansions) for arg in ctx.attr.arguments]
    ctx.actions.write(spec, json.encode({
        "id": ctx.attr.lint_id,
        "sources": mapping,
        "executable": ctx.executable.tool.path,
        "arguments": arguments,
        "cwd": ctx.attr.cwd,
        "go": ctx.expand_location(ctx.attr.go, targets = expansions) if ctx.attr.go else "",
        "module_cache": [f.path for f in ctx.files.module_cache],
    }))
    ctx.actions.run(
        executable = ctx.executable._runner,
        arguments = [spec.path, result.path],
        inputs = depset([spec] + sources + ctx.files.data + ctx.files.module_cache),
        tools = tools + [ctx.attr.tool[DefaultInfo].files_to_run],
        outputs = [result],
        mnemonic = "HovelLint",
        progress_message = "Checking " + ctx.attr.lint_id,
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([result]))]

lint_action = rule(
    implementation = _impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "source_prefix": attr.string(),
        "prefixes": attr.string_list(),
        "suffixes": attr.string_list(),
        "lint_id": attr.string(mandatory = True),
        "tool": attr.label(executable = True, cfg = "exec", mandatory = True),
        "tools": attr.label_list(cfg = "exec", allow_files = True),
        "data": attr.label_list(cfg = "exec", allow_files = True),
        "arguments": attr.string_list(),
        "cwd": attr.string(default = "."),
        "go": attr.string(),
        "module_cache": attr.label_list(allow_files = True),
        "_runner": attr.label(default = Label("//tools/lint:lint_action_runner"), executable = True, cfg = "exec"),
    },
)

def checked_lint(name, **kwargs):
    """Declare a reusable result and a test enforcing its status."""
    lint_action(name = name + "_result", **kwargs)
    py_test(
        name = name + "_test",
        srcs = ["lint_result_test.py"],
        main = "lint_result_test.py",
        args = ["$(rootpath :" + name + "_result)"],
        data = [":" + name + "_result"],
    )

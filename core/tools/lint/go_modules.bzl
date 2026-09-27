"""Resolve checksum-locked Go archives for offline lint actions."""

def _impl(ctx):
    go = ctx.path(ctx.attr.go)
    mod = ctx.read(ctx.attr.go_mod)
    sums = ctx.read(ctx.attr.go_sum)
    ctx.file("workspace/go.mod", mod)
    ctx.file("workspace/go.sum", sums)
    result = ctx.execute(
        [str(go), "mod", "download"],
        working_directory = "workspace",
        environment = {
            "GOENV": "off",
            "GOTOOLCHAIN": "local",
            "GOPROXY": "https://proxy.golang.org",
            "GOSUMDB": "sum.golang.org",
            "GOFLAGS": "-mod=readonly",
            "GOMODCACHE": str(ctx.path("modules")),
            "GOPATH": str(ctx.path("gopath")),
            "GOCACHE": str(ctx.path("build-cache")),
        },
        timeout = 600,
    )
    if result.return_code:
        fail("Cannot fetch locked lint dependencies: " + result.stderr)
    if ctx.read("workspace/go.sum") != sums or ctx.read("workspace/go.mod") != mod:
        fail("Lint dependency download changed go.mod/go.sum; update the checked-in lock")
    ctx.file("BUILD.bazel", 'filegroup(name = "downloads", srcs = glob(["modules/cache/download/**"], exclude = ["**/*.lock", "**/list"]), visibility = ["//visibility:public"])\n')

go_modules = repository_rule(
    implementation = _impl,
    attrs = {
        "go": attr.label(mandatory = True, allow_single_file = True),
        "go_mod": attr.label(mandatory = True, allow_single_file = True),
        "go_sum": attr.label(mandatory = True, allow_single_file = True),
    },
)

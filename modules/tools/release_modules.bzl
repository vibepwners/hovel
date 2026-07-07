"""Release host matrix for compiled example modules."""

load("//modules/tools:platform_binary.bzl", "platform_binary")

MODULE_HOSTS = [
    struct(
        arch = "amd64",
        dir = "linux-amd64",
        exe = "",
        key = "linux_amd64",
        os = "linux",
        platform = "//platforms:linux_x86_64",
        suffix = "release-linux-amd64",
    ),
    struct(
        arch = "arm64",
        dir = "linux-arm64",
        exe = "",
        key = "linux_arm64",
        os = "linux",
        platform = "//platforms:linux_aarch64_musl",
        suffix = "release-linux-arm64",
    ),
    struct(
        arch = "arm64",
        dir = "darwin-arm64",
        exe = "",
        key = "darwin_arm64",
        os = "darwin",
        platform = "//platforms:darwin_aarch64",
        suffix = "release-darwin-arm64",
    ),
]

LINUX_HOSTS = [
    host
    for host in MODULE_HOSTS
    if host.os == "linux"
]

COMPILED_MODULES = [
    struct(binary = "//modules/examples/go/mock_survey:mock_survey", command = "mock-survey-go", hosts = MODULE_HOSTS, key = "mock_survey_go"),
    struct(binary = "//modules/examples/go/mock_exploit:mock_exploit", command = "mock-exploit-go", hosts = MODULE_HOSTS, key = "mock_exploit_go"),
    struct(binary = "//modules/examples/go/mock_exploit_session:mock_exploit_session", command = "mock-exploit-session-go", hosts = MODULE_HOSTS, key = "mock_exploit_session_go"),
    struct(binary = "//modules/examples/rust/mock_survey:mock-survey-rust", command = "mock-survey-rust", hosts = LINUX_HOSTS, key = "mock_survey_rust"),
    struct(binary = "//modules/examples/rust/mock_exploit:mock-exploit-rust", command = "mock-exploit-rust", hosts = LINUX_HOSTS, key = "mock_exploit_rust"),
    struct(binary = "//modules/examples/rust/mock_exploit_session:mock-exploit-session-rust", command = "mock-exploit-session-rust", hosts = LINUX_HOSTS, key = "mock_exploit_session_rust"),
    struct(binary = "//modules/squatter/provider:squatter-provider", command = "squatter-provider", hosts = MODULE_HOSTS, key = "squatter_provider"),
]

def release_module_target_name(module, host):
    return "{}_{}".format(module.key, host.key)

def declare_release_module_binaries(name):
    """Declares platform-specific binary staging targets for compiled modules.

    Args:
      name: Conventional macro name for BUILD-file tooling.
    """
    for module in COMPILED_MODULES:
        for host in module.hosts:
            platform_binary(
                name = release_module_target_name(module, host),
                binary = module.binary,
                out = "{}/{}{}".format(host.dir, module.command, host.exe),
                platform = host.platform,
                platform_suffix = host.suffix,
            )

def release_module_stage_args():
    """Returns stage_examples/package_examples arguments for compiled modules.

    Returns:
      A list of `--module=...` arguments using rootpath expansions.
    """
    args = []
    for module in COMPILED_MODULES:
        for host in module.hosts:
            name = release_module_target_name(module, host)
            staged = "{}/{}{}".format(host.dir, module.command, host.exe)
            args.append("--module={}=$(rootpath :{})".format(staged, name))
    return args

def release_module_data():
    """Returns data dependencies for all compiled module staging targets.

    Returns:
      A list of Bazel labels for every compiled module staging target.
    """
    data = []
    for module in COMPILED_MODULES:
        for host in module.hosts:
            data.append(":{}".format(release_module_target_name(module, host)))
    return data

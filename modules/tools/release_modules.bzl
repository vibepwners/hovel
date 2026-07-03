"""Release host matrix for compiled example modules."""

load("//tools/modules:platform_binary.bzl", "platform_binary")

SUPPORTED_HOSTS = [
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
        arch = "amd64",
        dir = "windows-amd64",
        exe = ".exe",
        key = "windows_amd64",
        os = "windows",
        platform = "//platforms:windows_x86_64",
        suffix = "release-windows-amd64",
    ),
    struct(
        arch = "arm64",
        dir = "windows-arm64",
        exe = ".exe",
        key = "windows_arm64",
        os = "windows",
        platform = "//platforms:windows_aarch64",
        suffix = "release-windows-arm64",
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

COMPILED_MODULES = [
    struct(binary = "//examples/go/mock_survey:mock_survey", command = "mock-survey-go", key = "mock_survey_go"),
    struct(binary = "//examples/go/mock_exploit:mock_exploit", command = "mock-exploit-go", key = "mock_exploit_go"),
    struct(binary = "//examples/go/mock_exploit_session:mock_exploit_session", command = "mock-exploit-session-go", key = "mock_exploit_session_go"),
    struct(binary = "//examples/rust/mock_survey:mock-survey-rust", command = "mock-survey-rust", key = "mock_survey_rust"),
    struct(binary = "//examples/rust/mock_exploit:mock-exploit-rust", command = "mock-exploit-rust", key = "mock_exploit_rust"),
    struct(binary = "//examples/rust/mock_exploit_session:mock-exploit-session-rust", command = "mock-exploit-session-rust", key = "mock_exploit_session_rust"),
    struct(binary = "//payloads/squatter/provider:squatter-provider", command = "squatter-provider", key = "squatter_provider"),
]

def release_module_target_name(module, host):
    return "{}_{}".format(module.key, host.key)

def declare_release_module_binaries():
    for module in COMPILED_MODULES:
        for host in SUPPORTED_HOSTS:
            platform_binary(
                name = release_module_target_name(module, host),
                binary = module.binary,
                out = "{}/{}{}".format(host.dir, module.command, host.exe),
                platform = host.platform,
                platform_suffix = host.suffix,
            )

def release_module_stage_args():
    args = []
    for module in COMPILED_MODULES:
        for host in SUPPORTED_HOSTS:
            name = release_module_target_name(module, host)
            staged = "{}/{}{}".format(host.dir, module.command, host.exe)
            args.append("--module={}=$(rootpath :{})".format(staged, name))
    return args

def release_module_data():
    data = []
    for module in COMPILED_MODULES:
        for host in SUPPORTED_HOSTS:
            data.append(":{}".format(release_module_target_name(module, host)))
    return data

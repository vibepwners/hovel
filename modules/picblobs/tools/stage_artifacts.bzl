"""Declared artifact graph for Picblobs package staging."""

load(
    "//modules/picblobs/bazel:platforms.bzl",
    "BLOB_STAGE_ARTIFACTS",
    "RUNNER_STAGE_ARTIFACTS",
    "UL_EXEC_STAGE_ARTIFACTS",
)
load("//modules/picblobs/bazel:transition.bzl", "platform_filegroup")

def _safe(value):
    return value.replace(":", "_").replace("/", "_").replace("-", "_")

def _artifact_name(kind, *parts):
    return kind + "__" + "__".join([_safe(part) for part in parts])

def declare_stage_artifacts(name_prefix = "stage", include_runners = True):
    """Declare transitioned artifacts and return py_binary data/args.

    Args:
      name_prefix: Prefix used for generated filegroup target names.
      include_runners: Whether runner and test binary artifacts should be included.

    Returns:
      A struct with py_binary args and data attributes for the staged artifacts.
    """
    data = []
    args = []

    for target, staged_name, os_name, arch_name, platform in BLOB_STAGE_ARTIFACTS:
        name = _artifact_name(name_prefix + "_blob", os_name, arch_name, target)
        platform_filegroup(
            name = name,
            deps = ["//modules/picblobs/src/payload:" + target],
            platform = platform,
        )
        data.append(":" + name)
        args.append("--blob=%s:%s:%s:%s=$(rootpath :%s)" % (os_name, arch_name, target, staged_name, name))

    if include_runners:
        for runner_type, os_name, arch_name, platform in RUNNER_STAGE_ARTIFACTS:
            name = _artifact_name(name_prefix + "_runner", os_name, arch_name, runner_type)
            platform_filegroup(
                name = name,
                deps = ["//modules/picblobs/tests/runners/%s:runner" % runner_type],
                platform = platform,
            )
            data.append(":" + name)
            args.append("--runner=%s:%s:%s=$(rootpath :%s)" % (runner_type, os_name, arch_name, name))

        for fixture_type, os_name, arch_name, platform in UL_EXEC_STAGE_ARTIFACTS:
            name = _artifact_name(name_prefix + "_test_binary", fixture_type, os_name, arch_name)
            platform_filegroup(
                name = name,
                deps = ["//modules/picblobs/tests/ul_exec:hello_et_exec"],
                platform = platform,
            )
            data.append(":" + name)
            args.append("--test-binary=%s:%s:%s:hello_et_exec=$(rootpath :%s)" % (fixture_type, os_name, arch_name, name))

    return struct(
        args = args,
        data = data,
    )

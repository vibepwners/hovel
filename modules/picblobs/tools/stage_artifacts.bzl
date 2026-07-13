"""Declared artifact graph for Picblobs package staging."""

load(
    "//modules/picblobs/bazel:platforms.bzl",
    "BLOB_STAGE_ARTIFACTS",
    "RUNNER_STAGE_ARTIFACTS",
    "UL_EXEC_STAGE_ARTIFACTS",
)
load("//modules/picblobs/bazel:transition.bzl", "platform_artifact")

def _safe(value):
    return value.replace(":", "_").replace("/", "_").replace("-", "_")

def _artifact_name(kind, *parts):
    return kind + "__" + "__".join([_safe(part) for part in parts])

def _validate_specs(kind, requested, available):
    if requested == None:
        return

    unknown = [spec for spec in requested if spec not in available]
    if unknown:
        fail("unknown {} stage artifact specs: {}".format(kind, unknown))

    seen = {}
    duplicates = []
    for spec in requested:
        if spec in seen:
            duplicates.append(spec)
        seen[spec] = True
    if duplicates:
        fail("duplicate {} stage artifact specs: {}".format(kind, duplicates))

def declare_stage_artifacts(
        name_prefix = "stage",
        include_runners = True,
        blob_specs = None,
        runner_specs = None,
        test_binary_specs = None):
    """Declare transitioned artifacts and return py_binary data/args.

    Args:
      name_prefix: Prefix used for generated filegroup target names.
      include_runners: Whether runner and test binary artifacts should be included.
      blob_specs: Optional (target, OS, architecture) tuples to declare.
      runner_specs: Optional (runner type, OS, architecture) tuples to declare.
      test_binary_specs: Optional (fixture type, OS, architecture) tuples to declare.

    Returns:
      A struct with py_binary args and data attributes for the staged artifacts.
    """
    data = []
    args = []

    available_blobs = [
        (target, os_name, arch_name)
        for target, _staged_name, os_name, arch_name, _platform in BLOB_STAGE_ARTIFACTS
    ]
    available_runners = [
        (runner_type, os_name, arch_name)
        for runner_type, os_name, arch_name, _platform in RUNNER_STAGE_ARTIFACTS
    ]
    available_test_binaries = [
        (fixture_type, os_name, arch_name)
        for fixture_type, os_name, arch_name, _platform in UL_EXEC_STAGE_ARTIFACTS
    ]
    _validate_specs("blob", blob_specs, available_blobs)
    if not include_runners and (runner_specs != None or test_binary_specs != None):
        fail("runner/test-binary specs require include_runners = True")
    _validate_specs("runner", runner_specs, available_runners)
    _validate_specs("test-binary", test_binary_specs, available_test_binaries)

    for target, staged_name, os_name, arch_name, platform in BLOB_STAGE_ARTIFACTS:
        if blob_specs != None and (target, os_name, arch_name) not in blob_specs:
            continue
        name = _artifact_name(name_prefix + "_blob", os_name, arch_name, target)
        platform_artifact(
            name = name,
            dep = "//modules/picblobs/src/payload:" + target,
            platform = platform,
        )
        data.append(":" + name)
        args.append("--blob=%s:%s:%s:%s=$(rootpath :%s)" % (os_name, arch_name, target, staged_name, name))

    if include_runners:
        for runner_type, os_name, arch_name, platform in RUNNER_STAGE_ARTIFACTS:
            if runner_specs != None and (runner_type, os_name, arch_name) not in runner_specs:
                continue
            name = _artifact_name(name_prefix + "_runner", os_name, arch_name, runner_type)
            platform_artifact(
                name = name,
                dep = "//modules/picblobs/tests/runners/%s:runner" % runner_type,
                platform = platform,
            )
            data.append(":" + name)
            args.append("--runner=%s:%s:%s=$(rootpath :%s)" % (runner_type, os_name, arch_name, name))

        for fixture_type, os_name, arch_name, platform in UL_EXEC_STAGE_ARTIFACTS:
            if test_binary_specs != None and (fixture_type, os_name, arch_name) not in test_binary_specs:
                continue
            name = _artifact_name(name_prefix + "_test_binary", fixture_type, os_name, arch_name)
            platform_artifact(
                name = name,
                dep = "//modules/picblobs/tests/ul_exec:hello_et_exec",
                platform = platform,
            )
            data.append(":" + name)
            args.append("--test-binary=%s:%s:%s:hello_et_exec=$(rootpath :%s)" % (fixture_type, os_name, arch_name, name))

    return struct(
        args = args,
        data = data,
    )

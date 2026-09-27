"""Independent release rebuild manifests and allowlisted BuildBuddy evidence."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from ci_audit import request
from ci_summary import invocations

SCHEMA = "hovel.reproducibility/v1"
FLAGS = [
    "--remote_accept_cached=false",
    "--disk_cache=",
    "--remote_upload_local_results=false",
    "--remote_local_fallback=false",
    "--cache_test_results=no",
    "--remote_download_outputs=all",
    "--remote_default_exec_properties=recycle-runner=false",
    "--remote_default_exec_properties=preserve-workspace=false",
]
FAMILIES = {
    "hovel": ("core/dist", "*.whl", 5),
    "sdk": ("dist", "hovel_sdk-*", 2),
    "modules": ("dist/modules", "**/*", 15),
    "agent": ("dist/agent", "**/*", 4),
    "picblobs": ("modules/picblobs/dist/picblobs", "*", 2),
    "picblobs-cli": ("modules/picblobs/dist/picblobs-cli", "*", 2),
    "docs": ("_site", "**/*", 1),
}


def prepare(env: dict[str, str]) -> None:
    if env.get("HOVEL_BUILDBUDDY_MODE") != "remote-execution":
        raise ValueError("Independent rebuilds require BuildBuddy remote execution")
    replica = env.get("HOVEL_REPRO_REPLICA", "")
    if replica not in {"a", "b"}:
        raise ValueError("Expected independent replica a or b")
    directory = Path(env["RUNNER_TEMP"]) / ("hovel-repro-" + replica)
    directory.mkdir()  # Fail on reuse; never silently clean a previous build.
    output_root = directory / "output-root"
    setup = directory / "setup.json"
    settings = {
        "HOVEL_BAZEL_STARTUP_ARGS": shlex.join(shlex.split(env.get("HOVEL_BAZEL_STARTUP_ARGS", "")) + ["--output_user_root=" + str(output_root)]),
        "HOVEL_BAZEL_ARGS": shlex.join(shlex.split(env["HOVEL_BAZEL_ARGS"]) + FLAGS + ["--build_metadata=HOVEL_REPRO_REPLICA=" + replica]),
        "HOVEL_REPRO_SETUP": str(setup),
    }
    setup.write_text(json.dumps({
        "replica": replica, "fresh_output_root": not output_root.exists(),
        "output_root": str(output_root), "flags": FLAGS,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2) + "\n")
    with Path(env["GITHUB_ENV"]).open("a") as destination:
        for key, value in settings.items():
            if "\n" in value or "\r" in value:
                raise ValueError("Invalid runner environment value")
            destination.write(key + "=" + value + "\n")
    print("Prepared a new output root with action-cache reads and runner recycling disabled")


def file_manifest(root: Path, families: set[str] | None = None) -> dict:
    result = {}
    for family, (directory, pattern, minimum) in FAMILIES.items():
        if families is not None and family not in families:
            continue
        base = root / directory
        paths = sorted(path for path in base.glob(pattern) if path.is_file())
        if len(paths) < minimum:
            raise ValueError(f"Incomplete {family} artifacts: found {len(paths)}, expected at least {minimum}")
        records = {}
        for path in paths:
            if path.is_symlink():
                raise ValueError("Release artifacts must be regular files: " + str(path))
            data = path.read_bytes()
            records[path.relative_to(base).as_posix()] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        result[family] = records
    return result


def create_manifest(root: Path, setup_path: Path, output: Path) -> None:
    setup = json.loads(setup_path.read_text())
    if not setup["fresh_output_root"] or setup["flags"] != FLAGS:
        raise ValueError("Missing independent-build setup evidence")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "schema_version": SCHEMA, "commit": commit, "replica": setup["replica"],
        "fresh_output_root": True, "flags": FLAGS, "started_at": setup["started_at"],
        "artifacts": file_manifest(root),
    }, indent=2, sort_keys=True) + "\n")


def effective_options(directory: Path) -> dict:
    """Read only non-secret canonical options; never serialize raw BEP options."""
    result = {}
    wanted = {flag[2:].split("=", 1)[0] for flag in FLAGS} | {"remote_executor"}
    for path in directory.glob("*.json"):
        invocation_id = ""
        values = {}
        properties = {}
        for line in path.read_text().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "started" in event:
                invocation_id = event["started"].get("uuid", "")
            command = event.get("structuredCommandLine", {})
            if command.get("commandLineLabel") != "canonical":
                continue
            for section in command.get("sections", []):
                for option in section.get("optionList", {}).get("option", []):
                    name, value = option.get("optionName"), option.get("optionValue") or ""
                    if name not in wanted:
                        continue
                    if name == "remote_default_exec_properties":
                        key, _, setting = value.partition("=")
                        if key in {"recycle-runner", "preserve-workspace", "container-image", "network"}:
                            properties[key] = setting
                    else:
                        values[name] = value
        if invocation_id:
            result[invocation_id] = (values, properties)
    return result


def check_options(values: dict, properties: dict) -> None:
    for flag in FLAGS:
        name, _, expected = flag[2:].partition("=")
        if name == "remote_default_exec_properties":
            name, _, expected = expected.partition("=")
            actual = properties.get(name)
        else:
            actual = values.get(name)
        if actual != expected:
            raise ValueError("Canonical build options did not preserve " + name)
    if values.get("remote_executor") != "grpcs://vibepwners.buildbuddy.io":
        raise ValueError("Independent build did not use the expected remote executor")
    if properties.get("network") != "off" or not re.fullmatch(r"docker://[^\s]+@sha256:[a-f0-9]{64}", properties.get("container-image", "")):
        raise ValueError("Independent actions require a pinned image with networking disabled")


def execution_record(invocation: dict, key: str, started_at: str) -> dict:
    url = "https://vibepwners.buildbuddy.io/rpc/BuildBuddyService/GetExecution"
    records = json.loads(request(url, key, {
        "executionLookup": {"invocationId": invocation["id"]},
    })).get("execution", [])
    completed = 0
    for record in records:
        metadata = record.get("executedActionMetadata", {})
        start = metadata.get("executionStartTimestamp")
        end = metadata.get("executionCompletedTimestamp")
        if start and end and int(record.get("exitCode", 0)) == 0:
            begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
            finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if finish > begin >= datetime.fromisoformat(started_at):
                completed += 1
    return {"invocation_id": invocation["id"], "execution_records": len(records), "executed_actions": completed}


def verify_execution(path: Path, env: dict[str, str]) -> None:
    manifest = json.loads(path.read_text())
    current_flags = shlex.split(env["HOVEL_BAZEL_ARGS"])
    if not all(flag in current_flags for flag in FLAGS):
        raise ValueError("Independent rebuild flags were not preserved")
    key = env.get("BUILDBUDDY_API_KEY", "")
    if not key:
        raise ValueError("BuildBuddy execution evidence requires the API credential")
    completed = [item for item in invocations(Path(env["HOVEL_BEP_DIR"])) if item["status"] != "incomplete"]
    if not completed or any(item["status"] != "SUCCESS" for item in completed):
        raise ValueError("Independent rebuild contains missing or unsuccessful invocations")
    options = effective_options(Path(env["HOVEL_BEP_DIR"]))
    for invocation in completed:
        check_options(*options.get(invocation["id"], ({}, {})))
    with ThreadPoolExecutor(max_workers=4) as pool:
        evidence = list(pool.map(lambda invocation: execution_record(invocation, key, manifest["started_at"]), completed))
    for record in evidence:
        record["options_verified"] = True
        record["container_image"] = options[record["invocation_id"]][1]["container-image"]
    count = sum(item["executed_actions"] for item in evidence)
    if not count:
        raise ValueError("BuildBuddy did not confirm any actual action execution")
    manifest["execution"] = evidence
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"BuildBuddy confirmed {count} executed actions across {len(evidence)} invocations")


def compare(first: dict, second: dict) -> list[str]:
    differences = []
    for name, manifest in [("a", first), ("b", second)]:
        if manifest.get("schema_version") != SCHEMA or manifest.get("replica") != name:
            differences.append(name + ": invalid manifest identity")
        if not manifest.get("fresh_output_root") or manifest.get("flags") != FLAGS:
            differences.append(name + ": missing isolation evidence")
        if not sum(item.get("executed_actions", 0) for item in manifest.get("execution", [])):
            differences.append(name + ": missing actual execution evidence")
        if any(not item.get("options_verified") for item in manifest.get("execution", [])):
            differences.append(name + ": unverified canonical execution options")
        if set(manifest.get("artifacts", {})) != set(FAMILIES):
            differences.append(name + ": incomplete artifact families")
        for family, (_, _, minimum) in FAMILIES.items():
            if len(manifest.get("artifacts", {}).get(family, {})) < minimum:
                differences.append(name + ": incomplete " + family + " artifacts")
    if not re.fullmatch(r"[a-f0-9]{40}", first.get("commit", "")) or first.get("commit") != second.get("commit"):
        differences.append("source commits differ or are invalid")
    first_ids = {item["invocation_id"] for item in first.get("execution", [])}
    second_ids = {item["invocation_id"] for item in second.get("execution", [])}
    if first_ids & second_ids:
        differences.append("builds reused invocation evidence")
    try:
        if datetime.fromisoformat(second["started_at"]) < datetime.fromisoformat(first["finished_at"]):
            differences.append("independent builds overlapped")
    except (KeyError, ValueError):
        differences.append("missing independent build timestamps")
    first_images = {item.get("container_image") for item in first.get("execution", [])}
    second_images = {item.get("container_image") for item in second.get("execution", [])}
    if first_images != second_images or None in first_images:
        differences.append("execution images differ or are missing")
    for family in FAMILIES:
        a = first.get("artifacts", {}).get(family, {})
        b = second.get("artifacts", {}).get(family, {})
        for path in sorted(set(a) | set(b)):
            if a.get(path) != b.get(path):
                differences.append(f"{family}/{path}: {a.get(path)} != {b.get(path)}")
    return differences


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["prepare", "manifest", "verify", "compare", "verify-family"])
    parser.add_argument("--output", type=Path, default=Path("dist/reproducibility/manifest.json"))
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--families", default="")
    args = parser.parse_args()
    env = dict(os.environ)
    root = Path(env.get("BUILD_WORKSPACE_DIRECTORY", Path.cwd()))
    if args.operation == "prepare":
        prepare(env)
    elif args.operation == "manifest":
        create_manifest(root, Path(env["HOVEL_REPRO_SETUP"]), root / args.output)
    elif args.operation == "verify":
        verify_execution(root / args.output, env)
    elif args.operation == "verify-family":
        baseline = json.loads(args.first.read_text())
        families = set(args.families.split(","))
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        if not families or families - set(FAMILIES):
            raise ValueError("Unknown release artifact family")
        if baseline.get("schema_version") != SCHEMA or baseline.get("commit") != commit or baseline.get("replica") != "b":
            raise ValueError("Independent baseline does not match this release source")
        executions = baseline.get("execution", [])
        if baseline.get("flags") != FLAGS or not baseline.get("fresh_output_root") or not sum(item.get("executed_actions", 0) for item in executions) or not all(item.get("options_verified") for item in executions):
            raise ValueError("Independent baseline lacks execution evidence")
        current = file_manifest(root, families)
        if any(current[family] != baseline["artifacts"].get(family) for family in families):
            raise ValueError("Release artifacts differ from the independent rebuild")
        print("Release artifact hashes match the verified independent rebuild:", ", ".join(sorted(families)))
    else:
        differences = compare(json.loads(args.first.read_text()), json.loads(args.second.read_text()))
        result = {"schema_version": SCHEMA, "reproducible": not differences, "differences": differences}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print("Artifact comparison:", "FAILED" if differences else "PASSED")
        for difference in differences:
            print(difference)
        return int(bool(differences))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

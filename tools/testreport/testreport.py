from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


STATUS_ORDER = {"FAILED": 0, "ERROR": 1, "TIMEOUT": 2, "FLAKY": 3, "PASSED": 4, "SKIPPED": 5, "UNKNOWN": 6}


@dataclass
class TestCase:
    name: str
    classname: str = ""
    status: str = "PASSED"
    duration: float = 0.0
    message: str = ""
    output: str = ""


@dataclass
class TestTarget:
    label: str
    suite: str
    language: str
    status: str = "UNKNOWN"
    duration: float = 0.0
    attempts: int = 1
    shard: int = 0
    run: int = 1
    log_path: str = ""
    xml_path: str = ""
    raw_log_path: str = ""
    raw_xml_path: str = ""
    cases: list[TestCase] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)


@dataclass
class TestReport:
    title: str
    generated_at: str
    workflow: str
    job: str
    commit: str
    ref: str
    totals: dict[str, Any]
    targets: list[TestTarget]


def build_report(
    *,
    repo: Path,
    title: str,
    bep_files: list[Path],
    testlog_roots: list[Path],
    workflow: str,
    job: str,
    commit: str,
    ref: str,
    cache_roots: list[Path] | None = None,
) -> TestReport:
    targets: dict[str, TestTarget] = {}
    for bep in bep_files:
        if bep.is_file():
            ingest_bep(repo, bep, targets)
    has_bep_source = any(bep.is_file() and bep.stat().st_size > 0 for bep in bep_files)
    for root in testlog_roots:
        if root.is_dir():
            ingest_testlogs(repo, root, targets, allow_new=not has_bep_source)

    recover_bytestream_outputs(targets.values(), cache_roots or [])
    ordered = sorted(targets.values(), key=lambda target: (STATUS_ORDER.get(target.status, 99), target.suite, target.label))
    totals = summarize(ordered)
    return TestReport(
        title=title,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        workflow=workflow,
        job=job,
        commit=commit,
        ref=ref,
        totals=totals,
        targets=ordered,
    )


def ingest_bep(repo: Path, bep: Path, targets: dict[str, TestTarget]) -> None:
    for event in read_json_events(bep):
        result_id = event.get("id", {}).get("testResult")
        summary_id = event.get("id", {}).get("testSummary")
        if result_id:
            label = result_id.get("label", "unknown")
            target = targets.setdefault(label, new_target(label))
            target.run = int(result_id.get("run", target.run) or target.run)
            target.shard = int(result_id.get("shard", target.shard) or target.shard)
            target.attempts = max(target.attempts, int(result_id.get("attempt", target.attempts) or target.attempts))
            result = event.get("testResult", {})
            target.status = normalize_status(result.get("status", target.status))
            target.duration = max(target.duration, nanos_to_seconds(result.get("testAttemptDurationMillis")))
            for output in result.get("testActionOutput", []):
                name = output.get("name", "")
                path = uri_to_path(output.get("uri", ""), repo)
                if name == "test.log" and path:
                    target.raw_log_path = display_path(repo, path)
                elif name == "test.xml" and path:
                    target.raw_xml_path = display_path(repo, path)
                elif path:
                    target.outputs.append(display_path(repo, path))
        elif summary_id:
            label = summary_id.get("label", "unknown")
            target = targets.setdefault(label, new_target(label))
            summary = event.get("testSummary", {})
            target.status = normalize_status(summary.get("overallStatus", target.status))
            target.duration = max(target.duration, nanos_to_seconds(summary.get("totalRunDurationMillis")))
            target.attempts = max(target.attempts, int(summary.get("attemptCount", target.attempts) or target.attempts))


def ingest_testlogs(repo: Path, root: Path, targets: dict[str, TestTarget], *, allow_new: bool = True) -> None:
    for log in sorted(root.rglob("test.log")):
        label = label_from_log(root, log)
        if not allow_new and label not in targets:
            continue
        target = targets.setdefault(label, new_target(label))
        target.raw_log_path = display_path(repo, log)
        xml = log.with_name("test.xml")
        if xml.is_file():
            target.raw_xml_path = display_path(repo, xml)
            enrich_from_xml(target, xml)
        if target.status == "UNKNOWN":
            target.status = status_from_log(log)
        outputs = log.with_name("test.outputs")
        if outputs.is_dir():
            for path in sorted(item for item in outputs.rglob("*") if item.is_file()):
                target.outputs.append(display_path(repo, path))


def read_json_events(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        raw = json.loads(stripped)
        return raw if isinstance(raw, list) else []
    events = []
    for line in stripped.splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def enrich_from_xml(target: TestTarget, xml_path: Path) -> None:
    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="replace"))
    except ET.ParseError:
        return
    cases: list[TestCase] = []
    failures = errors = skipped = 0
    duration = 0.0
    for suite in root.findall(".//testsuite"):
        failures += int(suite.get("failures", "0") or "0")
        errors += int(suite.get("errors", "0") or "0")
        skipped += int(suite.get("skipped", "0") or "0")
        duration += parse_float(suite.get("time", "0"))
    for case in root.findall(".//testcase"):
        status = "PASSED"
        message = ""
        if case.find("failure") is not None:
            status = "FAILED"
            message = "".join(case.find("failure").itertext())
        elif case.find("error") is not None:
            status = "ERROR"
            message = "".join(case.find("error").itertext())
        elif case.find("skipped") is not None:
            status = "SKIPPED"
            message = "".join(case.find("skipped").itertext())
        output = "\n".join("".join(node.itertext()) for node in case.findall("system-out"))
        cases.append(
            TestCase(
                name=case.get("name", target.label),
                classname=case.get("classname", ""),
                status=status,
                duration=parse_float(case.get("time", case.get("duration", "0"))),
                message=message.strip(),
                output=output.strip(),
            )
        )
    if cases and not (len(cases) == 1 and cases[0].name == target.label and not cases[0].classname):
        target.cases = cases
    case_duration = sum(test_case.duration for test_case in cases)
    if duration:
        target.duration = max(target.duration, duration)
    elif case_duration:
        target.duration = max(target.duration, case_duration)
    if errors:
        target.status = "ERROR"
    elif failures:
        target.status = "FAILED"
    elif skipped and not cases:
        target.status = "SKIPPED"
    elif target.status == "UNKNOWN":
        target.status = "PASSED"


def render_report(report: TestReport, *, repo: Path, output: Path) -> None:
    if output.exists():
        shutil.rmtree(output)
    (output / "data").mkdir(parents=True)
    (output / "logs").mkdir()
    (output / "xml").mkdir()

    materialize_artifacts(report, repo, output)
    (output / "data/report.json").write_text(json.dumps(report_to_json(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def materialize_artifacts(report: TestReport, repo: Path, output: Path) -> None:
    for target in report.targets:
        slug = slugify(target.label)
        if target.raw_log_path:
            src = source_path(repo, target.raw_log_path)
            if src.is_file():
                dest = output / "logs" / f"{slug}.log"
                shutil.copy2(src, dest)
                target.log_path = display_path(output, dest)
        if target.raw_xml_path:
            src = source_path(repo, target.raw_xml_path)
            if src.is_file():
                dest = output / "xml" / f"{slug}.xml"
                shutil.copy2(src, dest)
                target.xml_path = display_path(output, dest)


def source_path(repo: Path, raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    return repo / path


def recover_bytestream_outputs(targets: Any, cache_roots: list[Path]) -> None:
    for target in targets:
        if target.raw_log_path.startswith("bytestream:"):
            recovered = recover_bytestream(target.raw_log_path, cache_roots)
            if recovered:
                target.raw_log_path = recovered.as_posix()
        if target.raw_xml_path.startswith("bytestream:"):
            recovered = recover_bytestream(target.raw_xml_path, cache_roots)
            if recovered:
                target.raw_xml_path = recovered.as_posix()


def recover_bytestream(uri: str, cache_roots: list[Path]) -> Path | None:
    match = re.search(r"/blobs/([a-fA-F0-9]{64})/(\d+)$", uri)
    if not match:
        return None
    digest = match.group(1).lower()
    for root in cache_roots:
        candidate = root / "cas" / digest[:2] / digest
        if candidate.is_file():
            return candidate.resolve()
    return None


def report_to_json(report: TestReport) -> dict[str, Any]:
    return asdict(report)


def summarize(targets: list[TestTarget]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    suites: dict[str, int] = {}
    suite_breakdown: dict[str, dict[str, Any]] = {}
    languages: dict[str, int] = {}
    cases = 0
    for target in targets:
        statuses[target.status] = statuses.get(target.status, 0) + 1
        suites[target.suite] = suites.get(target.suite, 0) + 1
        languages[target.language] = languages.get(target.language, 0) + 1
        cases += len(target.cases)
        suite = suite_breakdown.setdefault(
            target.suite,
            {
                "targets": 0,
                "cases": 0,
                "duration": 0.0,
                "statuses": {},
            },
        )
        suite["targets"] += 1
        suite["cases"] += len(target.cases)
        suite["duration"] = round(suite["duration"] + target.duration, 3)
        suite["statuses"][target.status] = suite["statuses"].get(target.status, 0) + 1
    return {
        "targets": len(targets),
        "cases": cases,
        "duration": round(sum(target.duration for target in targets), 3),
        "statuses": statuses,
        "suites": suites,
        "suite_breakdown": suite_breakdown,
        "languages": languages,
    }


def new_target(label: str) -> TestTarget:
    return TestTarget(label=label, suite=suite_for(label), language=language_for(label))


def normalize_status(status: str | None) -> str:
    value = (status or "UNKNOWN").upper()
    if value in {"PASSED", "FAILED", "FLAKY", "TIMEOUT", "SKIPPED", "ERROR"}:
        return value
    if value in {"NO_STATUS", "UNKNOWN_STATUS"}:
        return "UNKNOWN"
    return value


def status_from_log(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"\bFAIL(?:ED)?\b|FAILED TESTS|panic:", text):
        return "FAILED"
    if re.search(r"\bPASS\b|test result: ok|OK\b", text):
        return "PASSED"
    return "UNKNOWN"


def label_from_log(root: Path, log: Path) -> str:
    rel = log.parent.relative_to(root).as_posix()
    parts = rel.split("/")
    if not parts:
        return "//unknown:unknown"
    name = parts[-1]
    package = "/".join(parts[:-1])
    return f"//{package}:{name}" if package else f"//:{name}"


def suite_for(label: str) -> str:
    if label.startswith("//sdk/"):
        return "sdk"
    if label.startswith("//modules/examples/"):
        return "module examples"
    if label.startswith("//modules/"):
        return "modules"
    if label.startswith("//docs/"):
        return "docs"
    if label.startswith("//internal/") or label.startswith("//cmd/") or label.startswith("//schemas:") or label.startswith("//tools/"):
        return "core"
    return "root"


def language_for(label: str) -> str:
    path = label.split(":", 1)[0]
    name = label.split(":", 1)[-1]
    if "/rust/" in path or name.endswith("_rust_test") or "/rust" in path:
        return "rust"
    if (
        "/python" in path
        or name.endswith("_py_test")
        or "schema_smoke" in name
        or path.startswith("//tools/testreport")
        or path.startswith("//modules/tools")
        or path.startswith("//modules/squatter/windows")
        or path.startswith("//docs/")
    ):
        return "python"
    if "/squatter/tests" in path or name.endswith(".exe"):
        return "c/c++"
    if name.endswith("_test") or "/go/" in path or path.startswith("//internal/") or path.startswith("//cmd/"):
        return "go"
    return "unknown"


def uri_to_path(uri: str, repo: Path) -> Path | None:
    if not uri:
        return None
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme == "file":
        return Path(urllib.parse.unquote(parsed.path))
    path = Path(uri)
    if path.is_absolute():
        return path
    return repo / path


def display_path(root: Path, path: Path) -> str:
    root_abs = root.absolute()
    path_abs = path.absolute()
    try:
        return path_abs.relative_to(root_abs).as_posix()
    except ValueError:
        pass
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def nanos_to_seconds(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return round(float(value) / 1000.0, 3)
    except (TypeError, ValueError):
        return 0.0


def parse_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def slugify(value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip("/"))
    return f"{clean[:90]}-{digest}"

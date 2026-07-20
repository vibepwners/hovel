#!/usr/bin/env python3
"""Run the Squatter black-box functional suite for both Windows ABIs in Wine."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass


TRANSPORT_SURFACE = frozenset(
    {"tcp-bind-config", "tcp-callback-config", "smb-named-pipe"}
)
SERVICE_SURFACE = frozenset({"service-console-fallback", "service-scm"})
MESH_TLS_EVIDENCE = (
    "E2E workflow=generate-configure-stamp-launch pki=provider-stamped "
    "mesh=passthrough tls=wolfSSL/1.3 payload=real-wine tamper=fail-closed "
    "frames=Squatter-echo passed"
)

MODULE_DESCRIPTIONS = {
    "acl.stat": "reads file ACL ownership and SDDL",
    "cmd": "runs interactive and one-shot command sessions",
    "drive.list": "enumerates Windows drive roots and types",
    "echo": "round-trips arguments, Unicode, and stream data",
    "eventlog.query": "queries a bounded Windows event-log result set",
    "file.stat": "returns file metadata and SHA-256 evidence",
    "getfile": "downloads binary data and reports missing files",
    "payload.cleanup": "reports cleanup intent without stopping the fixture",
    "payload.status": "reports the live payload identity and uptime",
    "process.kill": "finds and terminates a live fixture process",
    "process.list": "enumerates processes and locates the payload",
    "process.run": "captures stdout, stderr, timeout, and exit code",
    "process.run_as_user": "launches through a selected process token",
    "putfile": "uploads and verifies a 4 MiB binary payload",
    "registry.query": "round-trips a Unicode registry value",
    "share.list": "enumerates or safely reports an empty share inventory",
    "wininfo": "collects host, user, architecture, token, and network data",
}

TRANSPORT_DESCRIPTIONS = {
    "tcp-bind-config": "configured TCP listener accepts a Squatter echo session",
    "tcp-callback-config": "configured reverse TCP callback completes an echo session",
    "smb-named-pipe": "Win32 named pipe carries a framed echo session",
}

SERVICE_DESCRIPTIONS = {
    "service-console-fallback": "dispatcher failure falls back to the configured console server",
    "service-scm": "SCM install, start, live session, control-stop, and delete succeed",
}


@dataclass(frozen=True)
class TestCaseResult:
    name: str
    status: str
    duration: float


@dataclass(frozen=True)
class Transcript:
    title: str
    output: str
    return_code: int
    duration: float


@dataclass(frozen=True)
class ABIEvidence:
    bits: int
    wine_arch: str
    modules: dict[str, tuple[str, ...]]
    transports: dict[str, tuple[str, ...]]
    services: dict[str, tuple[str, ...]]
    functional_tests: tuple[TestCaseResult, ...]
    provider_tests: tuple[TestCaseResult, ...]


class EvidenceRunner:
    def __init__(self) -> None:
        self.transcripts: list[Transcript] = []

    def write(self, text: str) -> None:
        print(text, end="", flush=True)

    def run(self, command: list[str], *, title: str) -> str:
        self.write(f"\n>>> BEGIN {title}\n")
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        output: list[str] = []
        for line in process.stdout:
            output.append(line)
            self.write(line)
        return_code = process.wait()
        duration = time.monotonic() - started
        contents = "".join(output)
        self.transcripts.append(
            Transcript(
                title=title, output=contents, return_code=return_code, duration=duration
            )
        )
        self.write(f"<<< END {title} | exit={return_code} | duration={duration:.2f}s\n")
        if return_code != 0:
            raise subprocess.CalledProcessError(return_code, command)
        return contents


def load_module_surface(path: pathlib.Path) -> frozenset[str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(raw, list)
        or not raw
        or any(not isinstance(name, str) or not name for name in raw)
    ):
        raise ValueError(f"invalid Squatter module surface: {path}")
    modules = frozenset(raw)
    if len(modules) != len(raw):
        raise ValueError(f"duplicate Squatter module in surface: {path}")
    return modules


def require_surface_markers(
    runner: EvidenceRunner, bits: int, output: str, module_surface: frozenset[str]
) -> tuple[int, int, int]:
    modules = set(re.findall(r"E2E module=([a-z0-9._]+)", output)) & module_surface
    transports = (
        set(re.findall(r"E2E transport=([a-z0-9._-]+)", output)) & TRANSPORT_SURFACE
    )
    services = (
        set(re.findall(r"E2E lifecycle=([a-z0-9._-]+)", output)) & SERVICE_SURFACE
    )
    missing = {
        "modules": sorted(module_surface - modules),
        "transports": sorted(TRANSPORT_SURFACE - transports),
        "service lifecycles": sorted(SERVICE_SURFACE - services),
    }
    missing = {name: values for name, values in missing.items() if values}
    if missing:
        runner.write(
            f"E2E {bits}-bit surface evidence is incomplete: {json.dumps(missing, sort_keys=True)}\n"
        )
        raise RuntimeError(f"Squatter {bits}-bit surface evidence is incomplete")
    runner.write(
        f"E2E {bits}-bit coverage validated: modules={len(modules)}/{len(module_surface)} "
        f"transports={len(transports)}/{len(TRANSPORT_SURFACE)} "
        f"service-lifecycles={len(services)}/{len(SERVICE_SURFACE)}\n"
    )
    return len(modules), len(transports), len(services)


def require_mesh_tls_marker(runner: EvidenceRunner, bits: int, output: str) -> int:
    count = output.count(MESH_TLS_EVIDENCE)
    if count != 1:
        runner.write(f"E2E {bits}-bit Mesh/TLS evidence count is {count}, want 1\n")
        raise RuntimeError(f"Squatter {bits}-bit Mesh/TLS evidence is incomplete")
    runner.write(
        f"E2E {bits}-bit stamped payload wolfSSL Mesh/TLS coverage validated: 1/1\n"
    )
    return 1


def parse_go_test_cases(output: str) -> tuple[TestCaseResult, ...]:
    results = []
    pattern = re.compile(r"^--- (PASS|FAIL|SKIP): (\S+) \(([0-9.]+)s\)$")
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            results.append(
                TestCaseResult(
                    name=match.group(2),
                    status=match.group(1),
                    duration=float(match.group(3)),
                )
            )
    return tuple(results)


def marker_test_map(
    output: str, marker: str, allowed: frozenset[str]
) -> dict[str, tuple[str, ...]]:
    tests: dict[str, set[str]] = {name: set() for name in allowed}
    current_test = "unattributed evidence"
    marker_pattern = re.compile(rf"E2E {re.escape(marker)}=([a-z0-9._-]+)")
    for line in output.splitlines():
        run_match = re.match(r"^=== RUN\s+(\S+)", line.strip())
        if run_match:
            current_test = run_match.group(1)
        for name in marker_pattern.findall(line):
            if name in tests:
                tests[name].add(current_test)
    return {name: tuple(sorted(names)) for name, names in sorted(tests.items())}


def build_abi_evidence(
    *,
    bits: int,
    wine_arch: str,
    functional_output: str,
    provider_output: str,
    module_surface: frozenset[str],
) -> ABIEvidence:
    return ABIEvidence(
        bits=bits,
        wine_arch=wine_arch,
        modules=marker_test_map(functional_output, "module", module_surface),
        transports=marker_test_map(functional_output, "transport", TRANSPORT_SURFACE),
        services=marker_test_map(functional_output, "lifecycle", SERVICE_SURFACE),
        functional_tests=parse_go_test_cases(functional_output),
        provider_tests=parse_go_test_cases(provider_output),
    )


def render_review_report(
    *,
    status: str,
    duration: float,
    module_surface: frozenset[str],
    abi_evidence: list[ABIEvidence],
    transcripts: list[Transcript],
    failure: str,
) -> str:
    by_bits = {evidence.bits: evidence for evidence in abi_evidence}
    lines = [
        "HOVEL / SQUATTER WINE END-TO-END REVIEW",
        "=" * 78,
        f"RESULT          : {status}",
        f"TOTAL DURATION  : {duration:.2f}s",
        "PAYLOADS        : PE32 (x86) and PE32+ (x64)",
        "RUNTIME         : isolated Wine containers",
        "SECURE PATH     : stamped PKI + Mesh passthrough + payload wolfSSL TLS 1.3",
    ]
    if failure:
        lines.append(f"FAILURE         : {failure}")
    lines.extend(
        [
            "",
            "REVIEW GUIDE",
            "------------",
            "1. Start with the coverage matrix below; every required cell must say PASS.",
            "2. Use each ABI checklist to see what was validated and by which test case.",
            "3. Review the timed test-case table for failures, skips, or unexpected duration.",
            "4. Use the raw transcript appendices only when command-level detail is needed.",
            "",
            "COVERAGE MATRIX",
            "---------------",
            f"{'CONTROL':<34} {'PE32 / x86':<18} {'PE32+ / x64':<18} TOTAL",
            f"{'-' * 34} {'-' * 18} {'-' * 18} {'-' * 12}",
            matrix_row(
                "Registered modules",
                by_bits,
                lambda item: len(present_markers(item.modules)),
                len(module_surface),
            ),
            matrix_row(
                "Configured transports",
                by_bits,
                lambda item: len(present_markers(item.transports)),
                len(TRANSPORT_SURFACE),
            ),
            matrix_row(
                "Service lifecycles",
                by_bits,
                lambda item: len(present_markers(item.services)),
                len(SERVICE_SURFACE),
            ),
            matrix_row(
                "Stamped payload Mesh/TLS",
                by_bits,
                lambda item: len(item.provider_tests),
                1,
            ),
        ]
    )

    for bits in (32, 64):
        evidence = by_bits.get(bits)
        lines.extend(render_abi_review(bits, evidence, module_surface))

    lines.extend(
        [
            "",
            "RAW TRANSCRIPT APPENDICES",
            "=" * 78,
            "The appendices preserve complete subprocess output after the reviewer-oriented",
            "summary. Runtime INFO/ERROR lines here are diagnostic context; pass/fail truth",
            "comes from command exit status, Go test results, and enforced E2E markers above.",
        ]
    )
    for index, transcript in enumerate(transcripts, start=1):
        lines.extend(
            [
                "",
                f"APPENDIX {index}: {transcript.title}",
                "-" * 78,
                f"Exit code: {transcript.return_code} | Duration: {transcript.duration:.2f}s",
                "--- BEGIN RAW OUTPUT ---",
                transcript.output.rstrip() or "<no subprocess output>",
                "--- END RAW OUTPUT ---",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def matrix_row(
    label: str,
    by_bits: dict[int, ABIEvidence],
    covered: Callable[[ABIEvidence], int],
    required_per_abi: int,
) -> str:
    cells = []
    total = 0
    for bits in (32, 64):
        evidence = by_bits.get(bits)
        if evidence is None:
            cells.append("NOT RUN")
            continue
        count = covered(evidence)
        total += count
        cells.append(
            f"{count}/{required_per_abi} {'PASS' if count == required_per_abi else 'FAIL'}"
        )
    total_required = required_per_abi * 2
    total_cell = (
        f"{total}/{total_required} {'PASS' if total == total_required else 'FAIL'}"
    )
    return f"{label:<34} {cells[0]:<18} {cells[1]:<18} {total_cell}"


def present_markers(markers: dict[str, tuple[str, ...]]) -> set[str]:
    return {name for name, tests in markers.items() if tests}


def render_abi_review(
    bits: int, evidence: ABIEvidence | None, module_surface: frozenset[str]
) -> list[str]:
    architecture = "PE32 / x86" if bits == 32 else "PE32+ / x64"
    if evidence is None:
        return [
            "",
            architecture,
            "=" * len(architecture),
            "[NOT RUN] No validated evidence was produced.",
        ]

    functional_passed = sum(
        result.status == "PASS" for result in evidence.functional_tests
    )
    provider_passed = sum(result.status == "PASS" for result in evidence.provider_tests)
    lines = [
        "",
        f"{architecture} REVIEW (WINEARCH={evidence.wine_arch})",
        "=" * 78,
        f"Functional cases : {functional_passed}/{len(evidence.functional_tests)} PASS",
        f"Mesh/TLS cases   : {provider_passed}/{len(evidence.provider_tests)} PASS",
        "",
        f"MODULE FEATURE SURFACE [{len(present_markers(evidence.modules))}/{len(module_surface)}]",
        "-" * 78,
    ]
    lines.extend(render_checklist(evidence.modules, MODULE_DESCRIPTIONS))
    lines.extend(
        [
            "",
            f"CONFIGURED TRANSPORTS [{len(present_markers(evidence.transports))}/{len(TRANSPORT_SURFACE)}]",
            "-" * 78,
        ]
    )
    lines.extend(render_checklist(evidence.transports, TRANSPORT_DESCRIPTIONS))
    lines.extend(
        [
            "",
            f"SERVICE LIFECYCLES [{len(present_markers(evidence.services))}/{len(SERVICE_SURFACE)}]",
            "-" * 78,
        ]
    )
    lines.extend(render_checklist(evidence.services, SERVICE_DESCRIPTIONS))
    lines.extend(
        [
            "",
            f"STAMPED PAYLOAD MESH / TLS [{provider_passed}/1]",
            "-" * 78,
            checklist_item(
                "stamped-payload-mesh-tls",
                bool(evidence.provider_tests)
                and all(case.status == "PASS" for case in evidence.provider_tests),
                "generates and configures the PE, stamps its complete PKI bundle, launches it under Wine, passes TLS through Mesh to payload wolfSSL, verifies the certificate and Squatter frames, then proves manifest and stamped-state tampering fail closed",
                tuple(case.name for case in evidence.provider_tests),
            ),
            "",
            "TIMED TEST CASES",
            "-" * 78,
            f"{'RESULT':<8} {'SECONDS':>8}  TEST CASE",
            f"{'-' * 8} {'-' * 8}  {'-' * 44}",
        ]
    )
    for case in (*evidence.functional_tests, *evidence.provider_tests):
        lines.append(f"{case.status:<8} {case.duration:>8.2f}  {case.name}")
    return lines


def render_checklist(
    markers: dict[str, tuple[str, ...]], descriptions: dict[str, str]
) -> list[str]:
    return [
        checklist_item(
            name,
            bool(tests),
            descriptions.get(name, "registered feature exercised"),
            tests,
        )
        for name, tests in markers.items()
    ]


def checklist_item(
    name: str, passed: bool, description: str, tests: tuple[str, ...]
) -> str:
    test_list = ", ".join(tests) if tests else "no evidence marker observed"
    return f"[{'PASS' if passed else 'FAIL'}] {name:<26} {description}\n       exercised by: {test_list}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dockerfile", type=pathlib.Path, required=True)
    parser.add_argument("--entrypoint", type=pathlib.Path, required=True)
    parser.add_argument("--functest", type=pathlib.Path, required=True)
    parser.add_argument("--provider-functest", type=pathlib.Path, required=True)
    parser.add_argument("--payload32", type=pathlib.Path, required=True)
    parser.add_argument("--payload64", type=pathlib.Path, required=True)
    parser.add_argument("--pipeprobe32", type=pathlib.Path, required=True)
    parser.add_argument("--pipeprobe64", type=pathlib.Path, required=True)
    parser.add_argument("--module-surface", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-log", type=pathlib.Path)
    parser.add_argument("--job-summary", type=pathlib.Path)
    parser.add_argument(
        "--image",
        default=os.environ.get(
            "HOVEL_SQUATTER_WINE_TEST_IMAGE",
            "hovel/squatter-wine-functional:local",
        ),
    )
    args = parser.parse_args()
    workspace = pathlib.Path(
        os.environ.get("BUILD_WORKSPACE_DIRECTORY", pathlib.Path.cwd())
    )
    if args.evidence_log is not None and not args.evidence_log.is_absolute():
        args.evidence_log = workspace / args.evidence_log
    if args.job_summary is not None and not args.job_summary.is_absolute():
        args.job_summary = workspace / args.job_summary

    inputs = {
        "Dockerfile": args.dockerfile,
        "entrypoint.sh": args.entrypoint,
        "functional test": args.functest,
        "provider mesh/TLS functional test": args.provider_functest,
        "32-bit payload": args.payload32,
        "64-bit payload": args.payload64,
        "32-bit named-pipe probe": args.pipeprobe32,
        "64-bit named-pipe probe": args.pipeprobe64,
        "module surface": args.module_surface,
    }
    for description, path in inputs.items():
        if not path.is_file():
            raise SystemExit(f"{description} not found: {path}")
    module_surface = load_module_surface(args.module_surface)

    started = time.monotonic()
    status = "FAILED"
    failure = ""
    module_cells = 0
    transport_cells = 0
    service_cells = 0
    mesh_tls_cells = 0
    runner = EvidenceRunner()
    abi_evidence: list[ABIEvidence] = []
    try:
        with tempfile.TemporaryDirectory(prefix="hovel-squatter-wine-") as directory:
            context = pathlib.Path(directory)
            shutil.copy2(args.dockerfile, context / "Dockerfile")
            shutil.copy2(args.entrypoint, context / "entrypoint.sh")
            runner.run(
                [
                    "docker",
                    "build",
                    "--pull=false",
                    "--tag",
                    args.image,
                    "--file",
                    str(context / "Dockerfile"),
                    str(context),
                ],
                title="Build pinned Squatter Wine image",
            )
        for bits, wine_arch, payload, pipeprobe in (
            (32, "win32", args.payload32, args.pipeprobe32),
            (64, "win64", args.payload64, args.pipeprobe64),
        ):
            functional_output = runner.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--init",
                    "--network=bridge",
                    "--env",
                    "HOVEL_SQUATTER_EXE=/payload/squatter.exe",
                    "--env",
                    "HOVEL_SQUATTER_REQUIRE_WINE=1",
                    "--env",
                    "HOVEL_SQUATTER_PIPE_PROBE=/payload/pipeprobe.exe",
                    "--env",
                    "HOVEL_SQUATTER_MODULE_SURFACE=/payload/module-surface.json",
                    "--env",
                    "HOVEL_SQUATTER_WINE=/usr/bin/wine",
                    "--env",
                    f"WINEARCH={wine_arch}",
                    "--volume",
                    f"{args.functest.resolve()}:/test/functest:ro",
                    "--volume",
                    f"{payload.resolve()}:/payload/squatter.exe:ro",
                    "--volume",
                    f"{pipeprobe.resolve()}:/payload/pipeprobe.exe:ro",
                    "--volume",
                    f"{args.module_surface.resolve()}:/payload/module-surface.json:ro",
                    "--entrypoint",
                    "/test/functest",
                    args.image,
                    "-test.v",
                    "-test.timeout=180s",
                ],
                title=f"PE{32 if bits == 32 else '32+'} / {bits}-bit functional suite",
            )
            modules, transports, services = require_surface_markers(
                runner, bits, functional_output, module_surface
            )
            module_cells += modules
            transport_cells += transports
            service_cells += services
            provider_output = runner.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--init",
                    "--network=bridge",
                    "--env",
                    "HOVEL_SQUATTER_EXE=/payload/squatter.exe",
                    "--env",
                    "HOVEL_SQUATTER_REAL_E2E=1",
                    "--env",
                    "HOVEL_SQUATTER_WINE=/usr/bin/wine",
                    "--env",
                    f"WINEARCH={wine_arch}",
                    "--volume",
                    f"{args.provider_functest.resolve()}:/test/provider-functest:ro",
                    "--volume",
                    f"{payload.resolve()}:/payload/squatter.exe:ro",
                    "--entrypoint",
                    "/test/provider-functest",
                    args.image,
                    "-test.v",
                    "-test.run=^TestProviderMeshTLSStreamCarriesRealWinePayload$",
                    "-test.timeout=120s",
                ],
                title=f"PE{32 if bits == 32 else '32+'} / {bits}-bit stamped payload wolfSSL Mesh/TLS suite",
            )
            mesh_tls_cells += require_mesh_tls_marker(runner, bits, provider_output)
            abi_evidence.append(
                build_abi_evidence(
                    bits=bits,
                    wine_arch=wine_arch,
                    functional_output=functional_output,
                    provider_output=provider_output,
                    module_surface=module_surface,
                )
            )
        status = "PASSED"
        return 0
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
        raise
    finally:
        duration = time.monotonic() - started
        review = render_review_report(
            status=status,
            duration=duration,
            module_surface=module_surface,
            abi_evidence=abi_evidence,
            transcripts=runner.transcripts,
            failure=failure,
        )
        summary = review.split("\nRAW TRANSCRIPT APPENDICES\n", 1)[0]
        runner.write(f"\n\n>>> HUMAN-READABLE E2E REVIEW\n\n{summary}\n")
        if args.evidence_log is not None:
            args.evidence_log.parent.mkdir(parents=True, exist_ok=True)
            args.evidence_log.write_text(review, encoding="utf-8")
        if args.job_summary is not None:
            args.job_summary.parent.mkdir(parents=True, exist_ok=True)
            args.job_summary.write_text(
                json.dumps(
                    {
                        "name": "Squatter Wine E2E (PE32 + PE32+)",
                        "category": "e2e",
                        "description": "Real Squatter payload feature, transport, service lifecycle, and provider Mesh/TLS matrix in isolated 32-bit and 64-bit Wine containers.",
                        "status": status,
                        "duration": round(duration, 3),
                        "raw_log_path": str(args.evidence_log or ""),
                        "coverage": [
                            {
                                "name": "Squatter modules × ABI",
                                "covered": module_cells,
                                "total": len(module_surface) * 2,
                                "minimum": 100.0,
                            },
                            {
                                "name": "Squatter transports × ABI",
                                "covered": transport_cells,
                                "total": len(TRANSPORT_SURFACE) * 2,
                                "minimum": 100.0,
                            },
                            {
                                "name": "Squatter service lifecycle × ABI",
                                "covered": service_cells,
                                "total": len(SERVICE_SURFACE) * 2,
                                "minimum": 100.0,
                            },
                            {
                                "name": "Squatter provider Mesh/TLS × ABI",
                                "covered": mesh_tls_cells,
                                "total": 2,
                                "minimum": 100.0,
                            },
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )


if __name__ == "__main__":
    raise SystemExit(main())

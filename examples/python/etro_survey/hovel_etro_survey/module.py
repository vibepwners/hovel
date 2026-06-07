from __future__ import annotations

from typing import ClassVar

from hovel_etro_survey.smb import (
    PIPE_WHITELIST,
    STATUS_ACCESS_DENIED,
    STATUS_INSUFF_SERVER_RESOURCES,
    STATUS_SUCCESS,
    SmbError,
    SmbResponse,
    SmbTouchClient,
)
from hovel_sdk import Artifact, Context, Finding, HovelModule, Requirement, Result

_DEFAULT_PORT = "445"
_DEFAULT_TIMEOUT = "10"

# Detection verdicts surfaced in outputs["facts"]["verdict"].
_VERDICT_VULNERABLE = "vulnerable"
_VERDICT_LIKELY_PATCHED = "likely_patched"
_VERDICT_UNREACHABLE = "unreachable"


def verdict_for_status(status: int) -> str:
    """Classify a PeekNamedPipe status code as a MS17-010 detection verdict."""
    if status == STATUS_INSUFF_SERVER_RESOURCES:
        return _VERDICT_VULNERABLE
    return _VERDICT_LIKELY_PATCHED


class EtroSurvey(HovelModule):
    name = "etro-survey"
    version = "v0.1.0"
    module_type = "survey"
    summary = "Fingerprint SMBv1 for the MS17-010 / EternalRomance vulnerability."
    description = (
        "Clean-room Smbtouch-equivalent survey. Opens an anonymous NULL session over "
        "SMBv1, tree-connects to IPC$, enumerates the EternalRomance pipe whitelist "
        "(spoolss/browser/lsarpc), and uses the PeekNamedPipe oracle to report whether "
        "srv.sys is vulnerable. Reconnaissance only; it never corrupts remote memory. "
        "Its facts (verdict, reachable pipe) feed the etro-exploit module."
    )
    tags: ClassVar[tuple[str, ...]] = ("smb", "ms17-010", "eternalromance", "survey", "python")
    target_config: ClassVar[tuple[Requirement, ...]] = (
        Requirement("target.host", "host", description="Target host name or IP address."),
        Requirement("target.port", "port", default=_DEFAULT_PORT, description="SMB TCP port (445 direct, 139 NBT)."),
        Requirement(
            "timeout_seconds",
            "int",
            required=False,
            default=_DEFAULT_TIMEOUT,
            description="Per-operation socket timeout in seconds.",
        ),
    )

    def run(self, ctx: Context) -> Result:
        host = str(ctx.input("target.host", ctx.target))
        port = int(ctx.input("target.port", _DEFAULT_PORT))
        timeout = float(ctx.input("timeout_seconds", _DEFAULT_TIMEOUT))
        ctx.log.info("starting SMBv1 touch", extra={"host": host, "port": port})

        try:
            with SmbTouchClient(host, port, timeout) as client:
                client.negotiate()
                client.session_setup_null()
                client.tree_connect_ipc()
                ctx.log.info("NULL session established to IPC$", extra={"host": host})
                peek = client.peek_named_pipe()
                pipes = _probe_pipes(client, ctx)
        except (SmbError, OSError) as exc:
            ctx.log.warning("touch could not reach SMBv1", extra={"host": host, "error": str(exc)})
            return _unreachable_result(host, port, str(exc))

        return _verdict_result(host, port, peek, pipes, ctx)


def _probe_pipes(client: SmbTouchClient, ctx: Context) -> list[str]:
    reachable: list[str] = []
    for pipe in PIPE_WHITELIST:
        try:
            response = client.open_pipe(pipe)
        except (SmbError, OSError) as exc:
            ctx.log.debug("pipe probe error", extra={"pipe": pipe, "error": str(exc)})
            continue
        if response.status in {STATUS_SUCCESS, STATUS_ACCESS_DENIED}:
            reachable.append(pipe)
            ctx.log.info("pipe reachable", extra={"pipe": pipe, "status": f"0x{response.status:08x}"})
    return reachable


def _verdict_result(host: str, port: int, peek: SmbResponse, pipes: list[str], ctx: Context) -> Result:
    verdict = verdict_for_status(peek.status)
    vulnerable = verdict == _VERDICT_VULNERABLE
    recommended = pipes[0] if pipes else ""
    facts = {
        "host": host,
        "port": port,
        "smb_reachable": True,
        "null_session": True,
        "verdict": verdict,
        "detection_status": f"0x{peek.status:08x}",
        "reachable_pipes": pipes,
        "recommended_pipe": recommended,
        # XP SP3 x86 is the only profile the matching exploit module supports.
        "suggested_target_profile": "XP_SP2SP3_X86" if vulnerable else "",
    }
    findings: list[Finding] = []
    if vulnerable:
        ctx.log.info("target reports MS17-010 vulnerable", extra={"host": host})
        findings.append(
            Finding(
                title="SMBv1 vulnerable to MS17-010 (EternalRomance family)",
                severity="critical",
                detail=(
                    f"{host}:{port} answered the PeekNamedPipe oracle with "
                    f"STATUS_INSUFF_SERVER_RESOURCES (0x{peek.status:08x}) over an anonymous NULL "
                    "session, indicating an unpatched srv.sys SMBv1 server. "
                    f"Reachable named pipes: {', '.join(pipes) or 'none'}."
                ),
            ),
        )
    else:
        findings.append(
            Finding(
                title="SMBv1 reachable but not MS17-010 vulnerable",
                severity="info",
                detail=(
                    f"{host}:{port} accepted a NULL session but the PeekNamedPipe oracle returned "
                    f"0x{peek.status:08x}, which does not match the vulnerable signature."
                ),
            ),
        )
    return Result.ok(
        {"facts": facts},
        summary=f"SMBv1 touch of {host}:{port}: {verdict}",
        findings=findings,
        artifacts=[Artifact.json("etro-survey-facts.json", facts)],
    )


def _unreachable_result(host: str, port: int, error: str) -> Result:
    facts = {
        "host": host,
        "port": port,
        "smb_reachable": False,
        "verdict": _VERDICT_UNREACHABLE,
        "error": error,
    }
    return Result.ok(
        {"facts": facts},
        summary=f"SMBv1 touch of {host}:{port}: unreachable ({error})",
        findings=[
            Finding(
                title="SMBv1 not reachable",
                severity="info",
                detail=f"Could not complete a NULL-session SMBv1 touch of {host}:{port}: {error}",
            ),
        ],
        artifacts=[Artifact.json("etro-survey-facts.json", facts)],
    )

from __future__ import annotations

import time
from typing import ClassVar

from hovel_sdk import Context, HovelModule, Requirement, Result


class MockSurvey(HovelModule):
    name = "mock-survey"
    version = "v0.0.0-example"
    module_type = "survey"
    summary = "Collect example target facts."
    description = "Example Python survey module for the Hovel stdio JSON-RPC runtime."
    tags: ClassVar[tuple[str, ...]] = ("example", "survey", "python")
    target_config: ClassVar[tuple[Requirement, ...]] = (
        Requirement("target.host", "host", description="Target host name or IP address."),
        Requirement("target.port", "port", description="Target TCP port."),
    )

    def run(self, ctx: Context) -> Result:
        host = ctx.input("target.host", ctx.target)
        port = ctx.input("target.port", "unknown")
        ctx.log.info("connecting to target %s:%s", host, port, extra={"host": host, "port": port})
        time.sleep(0.5)
        ctx.log.info("connected to target %s:%s, surveying ...", host, port, extra={"host": host, "port": port})
        time.sleep(1.5)
        ctx.log.info("example survey completed", extra={"host": host, "port": port})
        return Result.ok(
            {"facts": {"host": host, "port": port, "reachable": True}},
            summary=f"example survey reached {host}:{port}",
        )

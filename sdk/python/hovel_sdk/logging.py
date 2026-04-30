from __future__ import annotations

import logging
import traceback
from collections.abc import Callable
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())


class RPCLogHandler(logging.Handler):
    def __init__(self, emit: Callable[[dict[str, Any]], None]) -> None:
        super().__init__()
        self._emit = emit

    def emit(self, record: logging.LogRecord) -> None:
        fields: dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _RESERVED:
                continue
            fields[key] = value
        params: dict[str, Any] = {
            "level": record.levelname.lower(),
            "message": record.getMessage(),
            "logger": record.name,
            "fields": fields,
        }
        if record.exc_info:
            params["exception"] = "".join(traceback.format_exception(*record.exc_info))
        self._emit(params)


def setup_logging(emit: Callable[[dict[str, Any]], None] | None = None) -> RPCLogHandler:
    if emit is None:
        def emit(_params: dict[str, Any]) -> None:
            return

    handler = RPCLogHandler(emit)
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return handler

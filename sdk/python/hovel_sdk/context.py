from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Context:
    run_id: str
    module_id: str
    target: str
    inputs: dict[str, Any] = field(default_factory=dict)
    chain_config: dict[str, Any] = field(default_factory=dict)
    target_config: dict[str, Any] = field(default_factory=dict)
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("hovel.module"))

    def input(self, key: str, default: Any = None) -> Any:
        if key in self.inputs:
            return self.inputs[key]
        if key in self.target_config:
            return self.target_config[key]
        return self.chain_config.get(key, default)

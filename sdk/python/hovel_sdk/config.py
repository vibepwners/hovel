from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Requirement:
    key: str
    type: str = "string"
    required: bool = True
    default: str = ""
    description: str = ""
    allowed: list[str] = field(default_factory=list)
    secret: bool = False

    def to_rpc(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "type": self.type,
            "required": self.required,
            "default": self.default,
            "description": self.description,
            "allowed": list(self.allowed),
            "secret": self.secret,
        }

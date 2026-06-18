from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable
from typing import Any, ClassVar

from hovel_sdk.config import Requirement
from hovel_sdk.context import Context
from hovel_sdk.result import Result


class HovelModule(ABC):
    name: str = ""
    version: str = "0.0.0"
    summary: str = ""
    module_type: str = ""
    description: str = ""
    tags: ClassVar[tuple[str, ...]] = ()
    global_config: ClassVar[tuple[Requirement, ...]] = ()
    target_config: ClassVar[tuple[Requirement, ...]] = ()
    outputs: ClassVar[dict[str, Any]] = {}

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "description": self.description,
            "moduleType": self.module_type,
            "tags": list(self.tags),
        }

    def module_schema(self) -> dict[str, Any]:
        return {
            "chainConfig": [requirement.to_rpc() for requirement in self.global_config],
            "targetConfig": [requirement.to_rpc() for requirement in self.target_config],
            "outputs": dict(self.outputs),
        }

    def describe_steps(self) -> dict[str, Any]:
        return {"steps": []}

    def prepare_step(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement step.prepare")

    def execute_step(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement step.execute")

    def cleanup_step(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement step.cleanup")

    @abstractmethod
    def run(self, ctx: Context) -> Result | Awaitable[Result]:
        raise NotImplementedError

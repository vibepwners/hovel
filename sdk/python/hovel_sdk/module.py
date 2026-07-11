from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any, ClassVar

from hovel_sdk.config import Requirement
from hovel_sdk.context import Context
from hovel_sdk.mesh import (
    _MESH_RPC_BEACONS_METHOD,
    _MESH_RPC_LISTENER_START_METHOD,
    _MESH_RPC_LISTENER_STOP_METHOD,
    _MESH_RPC_LISTENERS_METHOD,
    _MESH_RPC_OPEN_STREAM_METHOD,
    _MESH_RPC_TASK_METHOD,
    _MESH_RPC_TOPOLOGY_METHOD,
)
from hovel_sdk.result import Result

if TYPE_CHECKING:
    from hovel_sdk.mesh import (
        MeshBeacon,
        MeshBeaconRequest,
        MeshDescribeRequest,
        MeshDescriptor,
        MeshListener,
        MeshListenerListRequest,
        MeshListenerStartRequest,
        MeshListenerStopRequest,
        MeshStreamRequest,
        MeshTaskRequest,
        MeshTaskResult,
        MeshTopology,
        MeshTopologyRequest,
    )
    from hovel_sdk.session import SessionRef


class HovelModule(ABC):
    name: str = ""
    version: str = ""
    summary: str = ""
    module_type: str = ""
    description: str = ""
    tags: ClassVar[tuple[str, ...]] = ()
    discovery_context: ClassVar[dict[str, Any]] = {}
    global_config: ClassVar[tuple[Requirement, ...]] = ()
    target_config: ClassVar[tuple[Requirement, ...]] = ()
    outputs: ClassVar[dict[str, Any]] = {}
    planning_context: ClassVar[dict[str, Any]] = {}

    def info(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "description": self.description,
            "moduleType": self.module_type,
            "tags": list(self.tags),
        }
        if self.discovery_context:
            info["discoveryContext"] = dict(self.discovery_context)
        return info

    def module_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "chainConfig": [requirement.to_rpc() for requirement in self.global_config],
            "targetConfig": [requirement.to_rpc() for requirement in self.target_config],
            "outputs": dict(self.outputs),
        }
        if self.planning_context:
            schema["planningContext"] = dict(self.planning_context)
        return schema

    def describe_steps(self) -> dict[str, Any]:
        return {"steps": []}

    def prepare_step(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement step.prepare")

    def execute_step(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement step.execute")

    def cleanup_step(self, request: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement step.cleanup")

    def describe_mesh(self, _request: MeshDescribeRequest) -> MeshDescriptor | Awaitable[MeshDescriptor]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} is not a mesh provider")

    def mesh_topology(self, _request: MeshTopologyRequest) -> MeshTopology | Awaitable[MeshTopology]:
        raise NotImplementedError(
            f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_TOPOLOGY_METHOD}"
        )

    def list_mesh_beacons(self, _request: MeshBeaconRequest) -> list[MeshBeacon] | Awaitable[list[MeshBeacon]]:
        raise NotImplementedError(
            f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_BEACONS_METHOD}"
        )

    def list_mesh_listeners(
        self,
        _request: MeshListenerListRequest,
    ) -> list[MeshListener] | Awaitable[list[MeshListener]]:
        raise NotImplementedError(
            f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_LISTENERS_METHOD}"
        )

    def start_mesh_listener(
        self,
        _request: MeshListenerStartRequest,
    ) -> MeshListener | Awaitable[MeshListener]:
        raise NotImplementedError(
            f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_LISTENER_START_METHOD}"
        )

    def stop_mesh_listener(
        self,
        _request: MeshListenerStopRequest,
    ) -> MeshListener | Awaitable[MeshListener]:
        raise NotImplementedError(
            f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_LISTENER_STOP_METHOD}"
        )

    def run_mesh_task(
        self,
        _ctx: Context,
        _request: MeshTaskRequest,
    ) -> MeshTaskResult | Awaitable[MeshTaskResult]:
        raise NotImplementedError(f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_TASK_METHOD}")

    def open_mesh_stream(
        self,
        _ctx: Context,
        _request: MeshStreamRequest,
    ) -> SessionRef | Awaitable[SessionRef]:
        raise NotImplementedError(
            f"{self.name or self.__class__.__name__} does not implement {_MESH_RPC_OPEN_STREAM_METHOD}"
        )

    @abstractmethod
    def run(self, ctx: Context) -> Result | Awaitable[Result]:
        raise NotImplementedError

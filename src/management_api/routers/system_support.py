"""P6 router composition, strict query and DTO helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from threading import RLock
from typing import Iterable

from fastapi import Request

from src.management_control import ErrorField, ManagementError, ManagementErrorCode
from src.management_control.network import NetworkControl
from src.management_control.system import ContentBlacklistControl, SettingsControl

from ..dependencies import ManagementRuntime, management_request_id
from ..schemas.base import ResponseMeta
from ._operations import operation_data


@dataclass(slots=True)
class SystemNetworkControls:
    settings: SettingsControl
    blacklist: ContentBlacklistControl
    network: NetworkControl


_BIND_LOCK = RLock()


def get_bound_system_network_controls(request: Request) -> SystemNetworkControls:
    runtime = getattr(request.app.state, "management_runtime", None)
    current = getattr(request.app.state, "management_system_network_controls", None)
    owner = getattr(request.app.state, "management_system_network_controls_runtime", None)
    if isinstance(current, SystemNetworkControls) and (owner is None or owner is runtime):
        return current
    if not isinstance(runtime, ManagementRuntime):
        raise ManagementError(ManagementErrorCode.SERVICE_NOT_READY, retryable=True)
    with _BIND_LOCK:
        current = getattr(request.app.state, "management_system_network_controls", None)
        owner = getattr(request.app.state, "management_system_network_controls_runtime", None)
        if isinstance(current, SystemNetworkControls) and (owner is None or owner is runtime):
            return current
        current = SystemNetworkControls(
            settings=SettingsControl(audit_sink=runtime.audit_sink),
            blacklist=ContentBlacklistControl(audit_sink=runtime.audit_sink),
            network=NetworkControl(operations=runtime.operations, audit_sink=runtime.audit_sink),
        )
        request.app.state.management_system_network_controls = current
        request.app.state.management_system_network_controls_runtime = runtime
        return current


def reject_unknown_query(*allowed: str):
    allowed_set = frozenset(allowed)

    async def dependency(request: Request) -> None:
        unknown = sorted(set(request.query_params.keys()) - allowed_set)
        if unknown:
            raise ManagementError(
                ManagementErrorCode.VALIDATION_FAILED,
                fields=tuple(ErrorField(key, "UNKNOWN_QUERY_PARAMETER", "Unknown query parameter") for key in unknown),
            )

    return dependency


def response_meta(request: Request) -> ResponseMeta:
    return ResponseMeta(requestId=management_request_id(request))


def success_response(status_code: int, data: dict) -> dict[int, dict]:
    return {
        status_code: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"data": data, "meta": {"requestId": "request-example"}}}},
        }
    }


def as_data(value) -> dict:
    return asdict(value)

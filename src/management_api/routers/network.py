"""Network settings, tested commits, cache and monitor Management API routes."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas.base import DataEnvelope
from ..schemas.network import (
    DnsCacheEntryData, DnsCacheEnvelope, DnsCacheListData,
    DnsTestRequest, NetworkCheckData, NetworkCheckEnvelope, NetworkCheckListData,
    NetworkCommitRequest, NetworkMonitorSettingsData, NetworkMonitorSettingsPatch,
    NetworkSettingsData, PageQuery, PageResponseMeta, Socks5StatePatch, Socks5TestRequest,
)
from ..schemas.operations import ManagementOperationData
from .system_support import (
    SystemNetworkControls, get_bound_system_network_controls, operation_data,
    reject_unknown_query, response_meta, success_response,
)


router = APIRouter()
ReadContext = Annotated[ManagementContext, Depends(require_capability(Capability.READ))]
WriteContext = Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))]
SecretContext = Annotated[ManagementContext, Depends(require_capability(Capability.SECRETS_WRITE))]
DestroyContext = Annotated[ManagementContext, Depends(require_capability(Capability.DESTRUCTIVE))]
Controls = Annotated[SystemNetworkControls, Depends(get_bound_system_network_controls)]
IfMatch = Annotated[str | None, Header(alias="If-Match")]
_ERRORS = (
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.ORIGIN_DENIED, ManagementErrorCode.CAPABILITY_DENIED,
    ManagementErrorCode.INVALID_REQUEST, ManagementErrorCode.CONFIRMATION_REQUIRED,
    ManagementErrorCode.VALIDATION_FAILED, ManagementErrorCode.RESOURCE_NOT_FOUND,
    ManagementErrorCode.REVISION_CONFLICT, ManagementErrorCode.STATE_CONFLICT,
    ManagementErrorCode.OPERATION_ALREADY_RUNNING, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
    ManagementErrorCode.SERVICE_NOT_READY,
)
_NETWORK_EXAMPLE = {
    "dns": {"servers": ["1.1.1.1"], "cacheTtlSeconds": 300},
    "socks5": {"enabled": True, "configured": True, "maskedUrl": "socks5://***:***@proxy.invalid:1080"},
    "proxySummary": {"proxyCount": 1, "groupCount": 1, "ruleCount": 2, "defaultRoute": "direct", "directFallback": False},
    "revision": "rev_example",
}
_OPERATION_EXAMPLE = {
    "id": "op_example", "kind": "network.dns.test", "status": "queued",
    "progress": None, "createdAt": "2026-01-02T03:04:05Z", "startedAt": None,
    "finishedAt": None, "result": None, "error": None, "cancellable": False,
}
_MONITOR_EXAMPLE = {
    "enabled": True, "intervalSeconds": 60, "dns": True, "socks5": False,
    "core": {"openai": True, "claude": True, "cloudflare": False},
    "channels": {"enabled": True, "byChannel": {"api:example": True}},
    "revision": "rev_example",
}


def _responses(status_code: int, example: dict):
    return {**success_response(status_code, example), **management_error_responses(*_ERRORS)}


def _network(value) -> NetworkSettingsData:
    return NetworkSettingsData.model_validate(asdict(value))


def _monitor(value) -> NetworkMonitorSettingsData:
    return NetworkMonitorSettingsData.model_validate(asdict(value))


def _page_meta(request: Request, value) -> PageResponseMeta:
    return PageResponseMeta(
        requestId=response_meta(request).requestId, page=value.page,
        pageSize=value.pageSize, total=value.total, hasNext=value.hasNext,
    )


@router.get("/network", operation_id="getNetworkSettings", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkSettingsData], responses=_responses(200, _NETWORK_EXAMPLE))
def get_network_settings(request: Request, context: ReadContext, controls: Controls):
    return DataEnvelope(data=_network(controls.network.get_settings(context)), meta=response_meta(request))


@router.post("/network/dns/tests", operation_id="testDnsSettings", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], status_code=status.HTTP_202_ACCEPTED, response_model=DataEnvelope[ManagementOperationData], responses=_responses(202, _OPERATION_EXAMPLE))
def test_dns_settings(body: DnsTestRequest, request: Request, context: WriteContext, controls: Controls):
    return DataEnvelope(data=operation_data(controls.network.start_dns_test(context, body.servers)), meta=response_meta(request))


@router.post("/network/dns/commits", operation_id="commitDnsSettings", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkSettingsData], responses=_responses(200, _NETWORK_EXAMPLE))
def commit_dns_settings(body: NetworkCommitRequest, request: Request, context: WriteContext, controls: Controls, if_match: IfMatch = None):
    value = controls.network.commit_dns(context, body.planId, force=body.force, expected_revision=if_match)
    return DataEnvelope(data=_network(value), meta=response_meta(request))


@router.post("/network/dns/actions/sync-system", operation_id="syncSystemDns", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkSettingsData], responses=_responses(200, _NETWORK_EXAMPLE))
def sync_system_dns(request: Request, context: WriteContext, controls: Controls, if_match: IfMatch = None):
    return DataEnvelope(data=_network(controls.network.sync_system_dns(context, expected_revision=if_match)), meta=response_meta(request))


@router.get("/network/dns/cache", operation_id="listDnsCache", dependencies=[Depends(reject_unknown_query("page", "pageSize"))], tags=["management-network"], response_model=DnsCacheEnvelope, responses=_responses(200, {"items": [], "revision": "rev_example"}))
def list_dns_cache(request: Request, query: Annotated[PageQuery, Query()], context: ReadContext, controls: Controls):
    value = controls.network.list_dns_cache(context, page=query.page, page_size=query.pageSize)
    return DnsCacheEnvelope(
        data=DnsCacheListData(items=[DnsCacheEntryData.model_validate(asdict(item)) for item in value.items], revision=value.revision),
        meta=_page_meta(request, value),
    )


@router.delete("/network/dns/cache", operation_id="clearDnsCache", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], status_code=status.HTTP_204_NO_CONTENT, responses={204: {"description": "DNS cache cleared"}, **management_error_responses(*_ERRORS)})
def clear_dns_cache(context: DestroyContext, controls: Controls) -> Response:
    controls.network.clear_dns_cache(context)
    return Response(status_code=204)


@router.post("/network/socks5/tests", operation_id="testSocks5Settings", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], status_code=status.HTTP_202_ACCEPTED, response_model=DataEnvelope[ManagementOperationData], responses=_responses(202, {**_OPERATION_EXAMPLE, "kind": "network.socks5.test"}))
def test_socks5_settings(body: Socks5TestRequest, request: Request, context: SecretContext, controls: Controls):
    return DataEnvelope(data=operation_data(controls.network.start_socks5_test(context, body.url)), meta=response_meta(request))


@router.post("/network/socks5/commits", operation_id="commitSocks5Settings", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkSettingsData], responses=_responses(200, _NETWORK_EXAMPLE))
def commit_socks5_settings(body: NetworkCommitRequest, request: Request, context: SecretContext, controls: Controls, if_match: IfMatch = None):
    value = controls.network.commit_socks5(context, body.planId, force=body.force, expected_revision=if_match)
    return DataEnvelope(data=_network(value), meta=response_meta(request))


@router.patch("/network/socks5", operation_id="updateSocks5State", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkSettingsData], responses=_responses(200, _NETWORK_EXAMPLE))
def update_socks5_state(body: Socks5StatePatch, request: Request, context: WriteContext, controls: Controls, if_match: IfMatch = None):
    value = controls.network.update_socks5_state(context, body.enabled, expected_revision=if_match)
    return DataEnvelope(data=_network(value), meta=response_meta(request))


@router.get("/network/monitor", operation_id="getNetworkMonitor", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkMonitorSettingsData], responses=_responses(200, _MONITOR_EXAMPLE))
def get_network_monitor(request: Request, context: ReadContext, controls: Controls):
    return DataEnvelope(data=_monitor(controls.network.get_monitor(context)), meta=response_meta(request))


@router.patch("/network/monitor", operation_id="updateNetworkMonitor", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], response_model=DataEnvelope[NetworkMonitorSettingsData], responses=_responses(200, _MONITOR_EXAMPLE))
def update_network_monitor(body: NetworkMonitorSettingsPatch, request: Request, context: WriteContext, controls: Controls, if_match: IfMatch = None):
    value = controls.network.update_monitor(context, body.model_dump(exclude_unset=True), expected_revision=if_match)
    return DataEnvelope(data=_monitor(value), meta=response_meta(request))


@router.get("/network/monitor/checks", operation_id="listNetworkChecks", dependencies=[Depends(reject_unknown_query("page", "pageSize"))], tags=["management-network"], response_model=NetworkCheckEnvelope, responses=_responses(200, {"items": [], "revision": "rev_example"}))
def list_network_checks(request: Request, query: Annotated[PageQuery, Query()], context: ReadContext, controls: Controls):
    value = controls.network.list_checks(context, page=query.page, page_size=query.pageSize)
    return NetworkCheckEnvelope(
        data=NetworkCheckListData(items=[NetworkCheckData.model_validate(asdict(item)) for item in value.items], revision=value.revision),
        meta=_page_meta(request, value),
    )


@router.post("/network/monitor/actions/run", operation_id="runNetworkMonitor", dependencies=[Depends(reject_unknown_query())], tags=["management-network"], status_code=status.HTTP_202_ACCEPTED, response_model=DataEnvelope[ManagementOperationData], responses=_responses(202, {**_OPERATION_EXAMPLE, "kind": "network.monitor.run"}))
def run_network_monitor(request: Request, context: WriteContext, controls: Controls):
    return DataEnvelope(data=operation_data(controls.network.run_monitor(context)), meta=response_meta(request))

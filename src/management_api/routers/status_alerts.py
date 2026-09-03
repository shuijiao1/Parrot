"""Status-alert Management API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response, status

from src.management_auth.principal import Capability
from src.management_control import ManagementContext, ManagementErrorCode
from src.management_control.auxiliary import AuxiliaryControls

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas.base import DataEnvelope
from ..schemas.operations import ManagementOperationData
from ..schemas.auxiliary_status import (
    PageResponseMeta,
    StatusAlertSettingsData,
    StatusAlertSettingsPatch,
    StatusIncidentData,
    StatusIncidentListData,
    StatusIncidentListEnvelope,
    StatusIncidentQuery,
)
from .auxiliary_support import (
    get_bound_auxiliary_controls,
    no_content_response,
    operation_data,
    reject_unknown_query,
    response_meta,
    success_response,
)


router = APIRouter()

_SETTINGS_EXAMPLE = {
    "data": {
        "enabled": True,
        "intervalSeconds": 60,
        "targets": ["claude", "openai", "cloudflare"],
        "minImpact": "minor",
        "notificationEnabled": True,
        "revision": "rev_example",
    },
    "meta": {"requestId": "request-example"},
}
_INCIDENT_EXAMPLE = {
    "id": "inc_example",
    "provider": "openai",
    "name": "Elevated errors",
    "impact": "major",
    "status": "investigating",
    "createdAt": "2026-01-02T03:04:05Z",
    "updatedAt": "2026-01-02T03:05:05Z",
    "shortlink": "https://status.example/incidents/example",
    "muted": False,
    "active": True,
    "mutedAt": None,
    "revision": "rev_example",
}
_LIST_EXAMPLE = {
    "data": {"items": [_INCIDENT_EXAMPLE]},
    "meta": {"requestId": "request-example", "page": 1, "pageSize": 50, "total": 1, "hasNext": False},
}
_INCIDENT_ENVELOPE_EXAMPLE = {"data": _INCIDENT_EXAMPLE, "meta": {"requestId": "request-example"}}
_OPERATION_EXAMPLE = {
    "data": {
        "id": "op_example",
        "kind": "status-alerts.refresh",
        "status": "queued",
        "progress": None,
        "createdAt": "2026-01-02T03:04:05Z",
        "startedAt": None,
        "finishedAt": None,
        "result": None,
        "error": None,
        "cancellable": False,
    },
    "meta": {"requestId": "request-example"},
}
_ERRORS = (
    ManagementErrorCode.SESSION_REQUIRED,
    ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.ORIGIN_DENIED,
    ManagementErrorCode.CAPABILITY_DENIED,
    ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.RESOURCE_NOT_FOUND,
    ManagementErrorCode.REVISION_CONFLICT,
    ManagementErrorCode.STATE_CONFLICT,
    ManagementErrorCode.UPSTREAM_ERROR,
    ManagementErrorCode.SERVICE_NOT_READY,
)


def _settings(value) -> StatusAlertSettingsData:
    return StatusAlertSettingsData(
        enabled=value.enabled,
        intervalSeconds=value.interval_seconds,
        targets=list(value.targets),
        minImpact=value.min_impact,
        notificationEnabled=value.notification_enabled,
        revision=value.revision,
    )


def _incident(value) -> StatusIncidentData:
    return StatusIncidentData(
        id=value.id,
        provider=value.provider,
        name=value.name,
        impact=value.impact,
        status=value.status,
        createdAt=value.created_at,
        updatedAt=value.updated_at,
        shortlink=value.shortlink,
        muted=value.muted,
        active=value.active,
        mutedAt=value.muted_at,
        revision=value.revision,
    )


@router.get(
    "/status-alerts/settings",
    operation_id="getStatusAlertSettings",
    dependencies=[Depends(reject_unknown_query())],
    tags=["status-alerts"],
    response_model=DataEnvelope[StatusAlertSettingsData],
    responses={**success_response(200, _SETTINGS_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def get_status_alert_settings(
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[StatusAlertSettingsData]:
    return DataEnvelope(data=_settings(controls.status_alerts.get_settings(context)), meta=response_meta(request))


@router.patch(
    "/status-alerts/settings",
    operation_id="updateStatusAlertSettings",
    dependencies=[Depends(reject_unknown_query())],
    tags=["status-alerts"],
    response_model=DataEnvelope[StatusAlertSettingsData],
    responses={**success_response(200, _SETTINGS_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def update_status_alert_settings(
    body: StatusAlertSettingsPatch,
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> DataEnvelope[StatusAlertSettingsData]:
    value = controls.status_alerts.update_settings(
        context,
        body.model_dump(exclude_unset=True),
        expected_revision=if_match,
    )
    return DataEnvelope(data=_settings(value), meta=response_meta(request))


@router.get(
    "/status-alerts/incidents",
    operation_id="listStatusIncidents",
    dependencies=[Depends(reject_unknown_query("view", "provider", "impact", "sort", "page", "pageSize"))],
    tags=["status-alerts"],
    response_model=StatusIncidentListEnvelope,
    responses={**success_response(200, _LIST_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def list_status_incidents(
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    filters: Annotated[StatusIncidentQuery, Query()],
) -> StatusIncidentListEnvelope:
    value = controls.status_alerts.list_incidents(
        context,
        view=filters.view,
        provider=filters.provider,
        impact=filters.impact,
        sort=filters.sort,
        page=filters.page,
        page_size=filters.pageSize,
    )
    return StatusIncidentListEnvelope(
        data=StatusIncidentListData(items=[_incident(item) for item in value.items]),
        meta=PageResponseMeta(
            requestId=response_meta(request).requestId,
            page=value.page,
            pageSize=value.page_size,
            total=value.total,
            hasNext=value.has_next,
        ),
    )


@router.post(
    "/status-alerts/actions/refresh",
    operation_id="refreshStatusAlerts",
    dependencies=[Depends(reject_unknown_query())],
    tags=["status-alerts"],
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DataEnvelope[ManagementOperationData],
    responses={**success_response(202, _OPERATION_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def refresh_status_alerts(
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
) -> DataEnvelope[ManagementOperationData]:
    operation = controls.status_alerts.refresh(context)
    return DataEnvelope(data=operation_data(operation), meta=response_meta(request))


@router.post(
    "/status-alerts/incidents/{incidentId}/actions/mute",
    operation_id="muteStatusIncident",
    dependencies=[Depends(reject_unknown_query())],
    tags=["status-alerts"],
    response_model=DataEnvelope[StatusIncidentData],
    responses={**success_response(200, _INCIDENT_ENVELOPE_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def mute_status_incident(
    incident_id: Annotated[str, Path(alias="incidentId", min_length=1, max_length=256)],
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> DataEnvelope[StatusIncidentData]:
    value = controls.status_alerts.mute_incident(context, incident_id, expected_revision=if_match)
    return DataEnvelope(data=_incident(value), meta=response_meta(request))


@router.delete(
    "/status-alerts/incidents/{incidentId}/mute",
    operation_id="unmuteStatusIncident",
    dependencies=[Depends(reject_unknown_query())],
    tags=["status-alerts"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**no_content_response("Status incident unmuted"), **management_error_responses(*_ERRORS)},
)
def unmute_status_incident(
    incident_id: Annotated[str, Path(alias="incidentId", min_length=1, max_length=256)],
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> Response:
    controls.status_alerts.unmute_incident(context, incident_id, expected_revision=if_match)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

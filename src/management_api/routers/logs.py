"""Request log list, detail and protected body endpoints."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode
from src.management_control.observability import (
    BodySort,
    LogBodyKind,
    RequestLogQuery,
    RequestLogSort,
    RequestLogStatus,
    RequestProtocol,
)

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas import DataEnvelope
from ..schemas.observability import (
    LogBodyItemData,
    LogBodyPagedEnvelope,
    PagedEnvelope,
    RawLogBodyData,
    RequestLogData,
    RequestLogDetailData,
    RequestLogFilterOptionsData,
)
from ._observability import body_paged_meta, controls, meta, paged_meta, reject_unknown_query


router = APIRouter(prefix="/logs", tags=["management-logs"])
_READ_ERRORS = management_error_responses(
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.CAPABILITY_DENIED, ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.RESOURCE_NOT_FOUND, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
)
_BODY_ERRORS = management_error_responses(
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.CAPABILITY_DENIED, ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.RESOURCE_NOT_FOUND, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
)


@router.get(
    "", operation_id="listRequestLogs",
    response_model=PagedEnvelope[RequestLogData], responses=_READ_ERRORS,
)
def list_request_logs(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    status: Annotated[list[RequestLogStatus] | None, Query()] = None,
    api_key: Annotated[list[str] | None, Query(alias="apiKey")] = None,
    model: Annotated[list[str] | None, Query()] = None,
    channel: Annotated[list[str] | None, Query()] = None,
    protocol: Annotated[list[RequestProtocol] | None, Query()] = None,
    query: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
    started_at: Annotated[datetime | None, Query(alias="startedAt")] = None,
    ended_at: Annotated[datetime | None, Query(alias="endedAt")] = None,
    sort: Annotated[RequestLogSort, Query()] = RequestLogSort.CREATED_AT,
    descending: Annotated[bool, Query()] = True,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> PagedEnvelope[RequestLogData]:
    reject_unknown_query(request, (
        "status", "apiKey", "model", "channel", "protocol", "query",
        "startedAt", "endedAt", "sort", "descending", "page", "pageSize",
    ))
    result = controls(request).logs.list_logs(context, RequestLogQuery(
        statuses=tuple(status or ()), api_keys=tuple(api_key or ()),
        models=tuple(model or ()), channels=tuple(channel or ()),
        protocols=tuple(protocol or ()), query=query,
        started_at=started_at, ended_at=ended_at, sort=sort,
        descending=descending, page=page, page_size=page_size,
    ))
    return PagedEnvelope(data=[RequestLogData.model_validate(item) for item in result.items], meta=paged_meta(request, result))


@router.get(
    "/filter-options", operation_id="getRequestLogFilterOptions",
    response_model=DataEnvelope[RequestLogFilterOptionsData], responses=_READ_ERRORS,
)
def get_request_log_filter_options(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[RequestLogFilterOptionsData]:
    reject_unknown_query(request, ())
    value = controls(request).logs.filter_options(context)
    return DataEnvelope(data=RequestLogFilterOptionsData.model_validate(value), meta=meta(request))


@router.get(
    "/{logId}/body", operation_id="getRequestLogBody",
    response_model=LogBodyPagedEnvelope, responses=_BODY_ERRORS,
)
def get_request_log_body(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.LOG_BODY_READ))],
    log_id: Annotated[str, Path(alias="logId", min_length=1, max_length=256)],
    kind: Annotated[LogBodyKind, Query()],
    query: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
    sort: Annotated[BodySort, Query()] = BodySort.ORIGINAL,
    item_kind: Annotated[str | None, Query(alias="itemKind", min_length=1, max_length=80)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> LogBodyPagedEnvelope:
    reject_unknown_query(request, ("kind", "query", "sort", "itemKind", "page", "pageSize"))
    result = controls(request).logs.body_items(
        context, log_id, kind=kind, query=query, sort=sort,
        item_kind=item_kind, page=page, page_size=page_size,
    )
    values = []
    for item in result.items:
        value = dict(item)
        value["id"] = f"item_{int(value.get('seq') or 0)}"
        values.append(LogBodyItemData.model_validate(value))
    return LogBodyPagedEnvelope(data=values, meta=body_paged_meta(request, result))


@router.get(
    "/{logId}/body/items/{itemId}", operation_id="getRequestLogBodyItem",
    response_model=DataEnvelope[LogBodyItemData], responses=_BODY_ERRORS,
)
def get_request_log_body_item(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.LOG_BODY_READ))],
    log_id: Annotated[str, Path(alias="logId", min_length=1, max_length=256)],
    item_id: Annotated[str, Path(alias="itemId", min_length=1, max_length=80)],
    kind: Annotated[LogBodyKind, Query()],
) -> DataEnvelope[LogBodyItemData]:
    reject_unknown_query(request, ("kind",))
    value = controls(request).logs.body_item(context, log_id, kind=kind, item_id=item_id)
    return DataEnvelope(data=LogBodyItemData.model_validate(value), meta=meta(request))


@router.get(
    "/{logId}/raw-body", operation_id="getRequestLogRawBody",
    response_model=DataEnvelope[RawLogBodyData], responses=_BODY_ERRORS,
)
def get_request_log_raw_body(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.LOG_BODY_READ))],
    log_id: Annotated[str, Path(alias="logId", min_length=1, max_length=256)],
    kind: Annotated[LogBodyKind, Query()],
) -> DataEnvelope[RawLogBodyData]:
    reject_unknown_query(request, ("kind",))
    value = controls(request).logs.raw_body(context, log_id, kind=kind)
    return DataEnvelope(data=RawLogBodyData.model_validate(value), meta=meta(request))


@router.get(
    "/{logId}", operation_id="getRequestLog",
    response_model=DataEnvelope[RequestLogDetailData], responses=_READ_ERRORS,
)
def get_request_log(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    log_id: Annotated[str, Path(alias="logId", min_length=1, max_length=256)],
) -> DataEnvelope[RequestLogDetailData]:
    reject_unknown_query(request, ())
    value = controls(request).logs.detail(context, log_id)
    return DataEnvelope(data=RequestLogDetailData.model_validate(value), meta=meta(request))

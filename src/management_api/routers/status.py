"""Read-only runtime status endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode
from src.management_control.observability.common import revision_for

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas import DataEnvelope
from ..schemas.observability import (
    BackgroundJobData,
    ConcurrencyData,
    CooldownData,
    RevisionedPagedEnvelope,
    RevisionedPagedResponseMeta,
    RuntimeStatusData,
)
from ._observability import controls, meta, paged_meta, reject_unknown_query


router = APIRouter(prefix="/runtime", tags=["management-runtime"])


def _revisioned(model_type, value):
    raw = dict(value)
    supplied = raw.pop("revision", None)
    public = {
        name: raw[name]
        for name in model_type.model_fields
        if name != "revision" and name in raw
    }
    public["revision"] = supplied or revision_for(public)
    return model_type.model_validate(public)


def _revisioned_page_meta(request: Request, result, values) -> RevisionedPagedResponseMeta:
    base = paged_meta(request, result).model_dump()
    snapshot = {
        "data": [value.model_dump(mode="json", exclude={"revision"}) for value in values],
        "page": result.page,
        "pageSize": result.page_size,
        "total": result.total,
        "hasNext": result.has_next,
    }
    return RevisionedPagedResponseMeta(**base, revision=revision_for(snapshot))


_ERRORS = management_error_responses(
    ManagementErrorCode.SESSION_REQUIRED,
    ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.CAPABILITY_DENIED,
    ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.SERVICE_NOT_READY,
    ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
)


@router.get(
    "/status", operation_id="getRuntimeStatus",
    response_model=DataEnvelope[RuntimeStatusData], responses=_ERRORS,
)
def get_runtime_status(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[RuntimeStatusData]:
    reject_unknown_query(request, ())
    value = dict(controls(request).status.runtime_status(context))
    value["concurrency"] = _revisioned(ConcurrencyData, value.get("concurrency") or {})
    return DataEnvelope(data=RuntimeStatusData.model_validate(value), meta=meta(request))


@router.get(
    "/background-jobs", operation_id="listBackgroundJobs",
    response_model=RevisionedPagedEnvelope[BackgroundJobData], responses=_ERRORS,
)
def list_background_jobs(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> RevisionedPagedEnvelope[BackgroundJobData]:
    reject_unknown_query(request, ("page", "pageSize"))
    result = controls(request).status.background_jobs(context, page=page, page_size=page_size)
    values = [_revisioned(BackgroundJobData, item) for item in result.items]
    return RevisionedPagedEnvelope(
        data=values, meta=_revisioned_page_meta(request, result, values),
    )


@router.get(
    "/cooldowns", operation_id="listCooldowns",
    response_model=RevisionedPagedEnvelope[CooldownData], responses=_ERRORS,
)
def list_cooldowns(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> RevisionedPagedEnvelope[CooldownData]:
    reject_unknown_query(request, ("page", "pageSize"))
    result = controls(request).status.cooldown_page(context, page=page, page_size=page_size)
    values = [_revisioned(CooldownData, item) for item in result.items]
    return RevisionedPagedEnvelope(
        data=values, meta=_revisioned_page_meta(request, result, values),
    )


@router.get(
    "/concurrency", operation_id="getConcurrencySnapshot",
    response_model=DataEnvelope[ConcurrencyData], responses=_ERRORS,
)
def get_concurrency_snapshot(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[ConcurrencyData]:
    reject_unknown_query(request, ())
    value = controls(request).status.api_concurrency_snapshot(context)
    return DataEnvelope(data=_revisioned(ConcurrencyData, value), meta=meta(request))

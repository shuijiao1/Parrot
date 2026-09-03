"""Read-only runtime status endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas import DataEnvelope
from ..schemas.observability import (
    BackgroundJobData,
    ConcurrencyData,
    CooldownData,
    PagedEnvelope,
    RuntimeStatusData,
)
from ._observability import controls, meta, paged_meta, reject_unknown_query


router = APIRouter(prefix="/runtime", tags=["management-runtime"])
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
    value = controls(request).status.runtime_status(context)
    return DataEnvelope(data=RuntimeStatusData.model_validate(value), meta=meta(request))


@router.get(
    "/background-jobs", operation_id="listBackgroundJobs",
    response_model=PagedEnvelope[BackgroundJobData], responses=_ERRORS,
)
def list_background_jobs(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> PagedEnvelope[BackgroundJobData]:
    reject_unknown_query(request, ("page", "pageSize"))
    result = controls(request).status.background_jobs(context, page=page, page_size=page_size)
    return PagedEnvelope(data=[BackgroundJobData.model_validate(item) for item in result.items], meta=paged_meta(request, result))


@router.get(
    "/cooldowns", operation_id="listCooldowns",
    response_model=PagedEnvelope[CooldownData], responses=_ERRORS,
)
def list_cooldowns(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> PagedEnvelope[CooldownData]:
    reject_unknown_query(request, ("page", "pageSize"))
    result = controls(request).status.cooldown_page(context, page=page, page_size=page_size)
    return PagedEnvelope(data=[CooldownData.model_validate(item) for item in result.items], meta=paged_meta(request, result))


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
    return DataEnvelope(data=ConcurrencyData.model_validate(value), meta=meta(request))

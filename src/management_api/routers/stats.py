"""Statistics and Telegram statistics-preference endpoints."""

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Path, Query, Request

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode
from src.management_control.observability import StatsBreakdownQuery, StatsDimension, StatsPeriod, StatsSort

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas import DataEnvelope
from ..schemas.observability import (
    ModelStatsData,
    PagedEnvelope,
    RecentCallData,
    StatsBreakdownData,
    StatsSummaryData,
    TelegramStatsPreferencesData,
    TelegramStatsPreferencesPatch,
)
from ._observability import controls, meta, paged_meta, reject_unknown_query


router = APIRouter(tags=["management-stats"])
_READ_ERRORS = management_error_responses(
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.CAPABILITY_DENIED, ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.RESOURCE_NOT_FOUND, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
)
_WRITE_ERRORS = management_error_responses(
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.CAPABILITY_DENIED, ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.REVISION_CONFLICT, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
)


@router.get(
    "/stats/summary", operation_id="getStatsSummary",
    response_model=DataEnvelope[StatsSummaryData], responses=_READ_ERRORS,
)
def get_stats_summary(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    period: Annotated[StatsPeriod, Query()] = StatsPeriod.TODAY,
) -> DataEnvelope[StatsSummaryData]:
    reject_unknown_query(request, ("period",))
    value = controls(request).stats.summary(context, period)
    return DataEnvelope(data=StatsSummaryData.model_validate(value), meta=meta(request))


@router.get(
    "/stats/breakdown", operation_id="getStatsBreakdown",
    response_model=PagedEnvelope[StatsBreakdownData], responses=_READ_ERRORS,
)
def get_stats_breakdown(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    dimension: Annotated[StatsDimension, Query()],
    period: Annotated[StatsPeriod, Query()] = StatsPeriod.TODAY,
    sort: Annotated[StatsSort, Query()] = StatsSort.TOTAL,
    descending: Annotated[bool, Query()] = True,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> PagedEnvelope[StatsBreakdownData]:
    reject_unknown_query(request, ("dimension", "period", "sort", "descending", "page", "pageSize"))
    result = controls(request).stats.breakdown(context, StatsBreakdownQuery(
        dimension=dimension, period=period, sort=sort, descending=descending,
        page=page, page_size=page_size,
    ))
    return PagedEnvelope(data=[StatsBreakdownData.model_validate(item) for item in result.items], meta=paged_meta(request, result))


@router.get(
    "/stats/models/{modelId}", operation_id="getModelStats",
    response_model=DataEnvelope[ModelStatsData], responses=_READ_ERRORS,
)
def get_model_stats(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    model_id: Annotated[str, Path(alias="modelId", min_length=1, max_length=256)],
    period: Annotated[StatsPeriod, Query()] = StatsPeriod.TODAY,
) -> DataEnvelope[ModelStatsData]:
    reject_unknown_query(request, ("period",))
    value = controls(request).stats.model_stats(context, model_id, period)
    return DataEnvelope(data=ModelStatsData.model_validate(value), meta=meta(request))


@router.get(
    "/stats/recent-calls", operation_id="listRecentCalls",
    response_model=PagedEnvelope[RecentCallData], responses=_READ_ERRORS,
)
def list_recent_calls(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> PagedEnvelope[RecentCallData]:
    reject_unknown_query(request, ("page", "pageSize"))
    result = controls(request).stats.recent_calls(context, page=page, page_size=page_size)
    values = []
    for row in result.items:
        values.append(RecentCallData(
            id=str(row.get("request_id") or row.get("id") or ""),
            status=str(row.get("status") or "unknown"),
            createdAt=row.get("created_at"),
            model=row.get("requested_model") or row.get("final_model"),
            channelId=row.get("final_channel_key"),
            durationMilliseconds=row.get("duration_ms") or row.get("total_time_ms"),
        ))
    return PagedEnvelope(data=values, meta=paged_meta(request, result))


@router.get(
    "/preferences/telegram/stats", operation_id="getTelegramStatsPreferences",
    response_model=DataEnvelope[TelegramStatsPreferencesData], responses=_READ_ERRORS,
)
def get_telegram_stats_preferences(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[TelegramStatsPreferencesData]:
    reject_unknown_query(request, ())
    value = controls(request).stats.get_preferences(context)
    return DataEnvelope(data=TelegramStatsPreferencesData.model_validate(value), meta=meta(request))


@router.patch(
    "/preferences/telegram/stats", operation_id="updateTelegramStatsPreferences",
    response_model=DataEnvelope[TelegramStatsPreferencesData], responses=_WRITE_ERRORS,
)
def update_telegram_stats_preferences(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    patch: Annotated[TelegramStatsPreferencesPatch, Body()],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> DataEnvelope[TelegramStatsPreferencesData]:
    reject_unknown_query(request, ())
    value = controls(request).stats.update_preferences(
        context, patch.model_dump(exclude_none=True), expected_revision=if_match,
    )
    return DataEnvelope(data=TelegramStatsPreferencesData.model_validate(value), meta=meta(request))

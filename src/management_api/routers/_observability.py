"""P4 router-only composition helpers; no business I/O lives here."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from fastapi import Request

from src.management_control import ErrorField, ManagementError, ManagementErrorCode
from src.management_control.observability import (
    DEFAULT_LOGS_CONTROL,
    DEFAULT_MEDIA_CONTROL,
    DEFAULT_RETENTION_CONTROL,
    DEFAULT_STATS_CONTROL,
    DEFAULT_STATUS_CONTROL,
    LogsControl,
    MediaControl,
    RetentionControl,
    StatsControl,
    StatusControl,
)
from src.management_control.operations import ManagementOperation

from ..dependencies import ManagementRuntime, management_request_id
from ..schemas import ManagementOperationData
from ..schemas.observability import LogBodyPagedResponseMeta, PagedResponseMeta
from ..schemas.operations import OperationErrorData, OperationProgressData


@dataclass(slots=True)
class ObservabilityControls:
    status: StatusControl = DEFAULT_STATUS_CONTROL
    stats: StatsControl = DEFAULT_STATS_CONTROL
    logs: LogsControl = DEFAULT_LOGS_CONTROL
    media: MediaControl = DEFAULT_MEDIA_CONTROL
    retention: RetentionControl = DEFAULT_RETENTION_CONTROL


def controls(request: Request) -> ObservabilityControls:
    """Return an explicit test seam or a control set owned by this runtime.

    Controls created here must not outlive (or accidentally bind to a different)
    ManagementRuntime because their mutation audit sink belongs to that runtime.
    """
    runtime = getattr(request.app.state, "management_runtime", None)
    current = getattr(request.app.state, "management_observability_controls", None)
    owner = getattr(request.app.state, "management_observability_controls_runtime", None)
    # Owner absent means the application explicitly supplied the whole control
    # set. Preserve that supported composition/test seam.
    if isinstance(current, ObservabilityControls) and (owner is None or owner is runtime):
        return current
    if not isinstance(runtime, ManagementRuntime):
        raise ManagementError(ManagementErrorCode.SERVICE_NOT_READY, retryable=True)
    current = ObservabilityControls(
        stats=StatsControl(audit_sink=runtime.audit_sink),
        retention=RetentionControl(audit_sink=runtime.audit_sink),
    )
    request.app.state.management_observability_controls = current
    request.app.state.management_observability_controls_runtime = runtime
    return current


def meta(request: Request) -> dict[str, str]:
    return {"requestId": management_request_id(request)}


def paged_meta(request: Request, result) -> PagedResponseMeta:
    return PagedResponseMeta(
        requestId=management_request_id(request),
        page=result.page,
        pageSize=result.page_size,
        total=result.total,
        hasNext=result.has_next,
    )


def body_paged_meta(request: Request, result) -> LogBodyPagedResponseMeta:
    return LogBodyPagedResponseMeta(
        requestId=management_request_id(request),
        page=result.page,
        pageSize=result.page_size,
        total=result.total,
        hasNext=result.has_next,
        kindCounts=list(result.kind_counts),
    )


def reject_unknown_query(request: Request, allowed: Iterable[str]) -> None:
    unknown = sorted(set(request.query_params.keys()) - set(allowed))
    if unknown:
        raise ManagementError(
            ManagementErrorCode.VALIDATION_FAILED,
            fields=tuple(
                ErrorField(path=field, code="extra_forbidden", message="Unknown query parameter")
                for field in unknown
            ),
        )


def operation_data(operation: ManagementOperation) -> ManagementOperationData:
    progress = None
    if operation.progress is not None:
        progress = OperationProgressData(
            current=operation.progress.current,
            total=operation.progress.total,
            messageCode=operation.progress.message_code,
        )
    error = None
    if operation.error is not None:
        error = OperationErrorData(
            code=operation.error.code,
            message=operation.error.message,
            retryable=operation.error.retryable,
        )
    return ManagementOperationData(
        id=operation.id,
        kind=operation.kind,
        status=operation.status,
        progress=progress,
        createdAt=operation.created_at,
        startedAt=operation.started_at,
        finishedAt=operation.finished_at,
        result=operation.result,
        error=error,
        cancellable=operation.cancellable,
    )

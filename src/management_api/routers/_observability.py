"""P4 router-only composition helpers; no business I/O lives here."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
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
from ..dependencies import ManagementRuntime, management_request_id
from ..schemas.observability import LogBodyPagedResponseMeta, PagedResponseMeta
from ._operations import operation_data


_binding_lock = RLock()


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
    with _binding_lock:
        # Double-check after acquiring the process-wide bind lock.  Concurrent
        # first requests for one runtime must never receive different retention
        # plan stores, or a plan created by one request can disappear at commit.
        current = getattr(request.app.state, "management_observability_controls", None)
        owner = getattr(request.app.state, "management_observability_controls_runtime", None)
        if isinstance(current, ObservabilityControls) and (owner is None or owner is runtime):
            return current
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

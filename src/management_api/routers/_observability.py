"""P4 router-only composition helpers; no business I/O lives here."""

from __future__ import annotations

from typing import Iterable

from fastapi import Request

from src.management_control import ErrorField, ManagementError, ManagementErrorCode
from src.management_control.composition import ObservabilityControls
from ..dependencies import (
    ManagementRuntime,
    get_management_control_owner,
    management_request_id,
)
from ..schemas.observability import LogBodyPagedResponseMeta, PagedResponseMeta
from ._operations import operation_data


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
    current = get_management_control_owner(runtime).observability
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
        revision=result.revision,
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

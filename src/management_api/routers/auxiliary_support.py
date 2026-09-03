"""Shared transport helpers for auxiliary-domain routers."""

from __future__ import annotations

from typing import Annotated, Callable

from fastapi import Depends, Request

from src.management_control.auxiliary import (
    AuxiliaryControls,
    ImageControl,
    StatusAlertControl,
    TranslationControl,
    UpdateControl,
    XaiMediaControl,
)
from src.management_control import ErrorField, ManagementError, ManagementErrorCode
from src.management_control.operations import ManagementOperation

from ..dependencies import ManagementRuntime, get_management_runtime, management_request_id
from ..schemas.base import ResponseMeta
from ..schemas.operations import ManagementOperationData, OperationErrorData, OperationProgressData


def get_bound_auxiliary_controls(
    request: Request,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
) -> AuxiliaryControls:
    current = getattr(request.app.state, "management_auxiliary_controls", None)
    owner = getattr(request.app.state, "management_auxiliary_controls_runtime", None)
    # Owner-less controls are an explicit composition/test seam. API-created
    # controls are runtime-owned and must never reuse Telegram's unaudited singleton.
    if isinstance(current, AuxiliaryControls) and (owner is None or owner is runtime):
        current.bind_operations(runtime.operations, runtime.operation_registry)
        return current
    current = AuxiliaryControls(
        translation=TranslationControl(audit_sink=runtime.audit_sink),
        status_alerts=StatusAlertControl(audit_sink=runtime.audit_sink),
        updates=UpdateControl(audit_sink=runtime.audit_sink),
        images=ImageControl(audit_sink=runtime.audit_sink),
        xai_media=XaiMediaControl(audit_sink=runtime.audit_sink),
    )
    current.bind_operations(runtime.operations, runtime.operation_registry)
    request.app.state.management_auxiliary_controls = current
    request.app.state.management_auxiliary_controls_runtime = runtime
    return current


def reject_unknown_query(*allowed: str) -> Callable[[Request], None]:
    """Build a route dependency that rejects undeclared query parameters."""
    allowed_names = frozenset(allowed)

    def guard(request: Request) -> None:
        unknown = sorted(set(request.query_params) - allowed_names)
        if not unknown:
            return
        raise ManagementError(
            ManagementErrorCode.VALIDATION_FAILED,
            fields=(
                ErrorField(
                    path=name,
                    code="UNKNOWN_QUERY_PARAMETER",
                    message="Unknown query parameter",
                )
                for name in unknown
            ),
        )

    return guard


def response_meta(request: Request) -> ResponseMeta:
    return ResponseMeta(requestId=management_request_id(request))


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


def success_response(status_code: int, example: dict) -> dict[int, dict]:
    return {
        status_code: {
            "description": "Successful Response",
            "content": {"application/json": {"example": example}},
        }
    }


def no_content_response(description: str) -> dict[int, dict]:
    return {
        204: {
            "description": description,
            "headers": {
                "X-Request-Id": {
                    "description": "Stable request correlation identifier",
                    "schema": {"type": "string"},
                    "example": "request-example",
                }
            },
        }
    }

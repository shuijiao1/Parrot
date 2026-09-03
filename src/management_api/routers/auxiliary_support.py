"""Shared transport helpers for auxiliary-domain routers."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from src.management_control.auxiliary import AuxiliaryControls, get_auxiliary_controls
from src.management_control.operations import ManagementOperation

from ..dependencies import ManagementRuntime, get_management_runtime, management_request_id
from ..schemas.base import ResponseMeta
from ..schemas.operations import ManagementOperationData, OperationErrorData, OperationProgressData


def get_bound_auxiliary_controls(
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
) -> AuxiliaryControls:
    controls = get_auxiliary_controls()
    controls.bind_operations(runtime.operations, runtime.operation_registry)
    return controls


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

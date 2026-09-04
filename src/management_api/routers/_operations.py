"""Shared public DTO mapping for ordinary Management Operations."""

from __future__ import annotations

from src.management_control.operations import ManagementOperation

from ..schemas.operations import (
    ManagementOperationData,
    OperationErrorData,
    OperationProgressData,
)


def operation_data(operation: ManagementOperation) -> ManagementOperationData:
    """Map an already-public ordinary Operation without changing its result."""
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

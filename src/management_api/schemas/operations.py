"""Typed public Operation schemas."""

from __future__ import annotations

from datetime import datetime
from pydantic import JsonValue

from src.management_control.errors import ManagementErrorCode
from src.management_control.operations import OperationStatus

from .base import StrictSchema


class OperationProgressData(StrictSchema):
    current: int
    total: int
    messageCode: str


class OperationErrorData(StrictSchema):
    code: ManagementErrorCode
    message: str
    retryable: bool


class ManagementOperationData(StrictSchema):
    id: str
    kind: str
    status: OperationStatus
    progress: OperationProgressData | None
    createdAt: datetime
    startedAt: datetime | None
    finishedAt: datetime | None
    result: JsonValue | None
    error: OperationErrorData | None
    cancellable: bool

"""Shared strict Management API envelope schemas."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

from src.management_control import ManagementErrorCode


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ResponseMeta(StrictSchema):
    requestId: str


DataT = TypeVar("DataT")


class DataEnvelope(StrictSchema, Generic[DataT]):
    data: DataT
    meta: ResponseMeta


class ErrorFieldSchema(StrictSchema):
    path: str
    code: str
    message: str


class ErrorDetailSchema(StrictSchema):
    code: ManagementErrorCode
    message: str
    fields: list[ErrorFieldSchema]
    retryable: bool
    requestId: str
    operationId: str | None = None


class ErrorEnvelope(StrictSchema):
    error: ErrorDetailSchema

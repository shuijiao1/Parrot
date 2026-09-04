"""Map transport-neutral management failures to the v1 HTTP envelope."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from types import MappingProxyType

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.management_control import ErrorField, ManagementError, ManagementErrorCode

from .dependencies import management_request_id
from .schemas import ErrorEnvelope


_MANAGEMENT_PREFIX = "/api/management/v1"


def is_management_path(path: str) -> bool:
    return path == _MANAGEMENT_PREFIX or path.startswith(f"{_MANAGEMENT_PREFIX}/")


MANAGEMENT_ERROR_STATUS: Mapping[ManagementErrorCode, int] = MappingProxyType({
    ManagementErrorCode.INVALID_REQUEST: 400,
    ManagementErrorCode.CONFIRMATION_REQUIRED: 400,
    ManagementErrorCode.INVALID_OPERATION_STATE: 400,
    ManagementErrorCode.SESSION_REQUIRED: 401,
    ManagementErrorCode.SESSION_EXPIRED: 401,
    ManagementErrorCode.AUTHENTICATION_FAILED: 401,
    ManagementErrorCode.CAPABILITY_DENIED: 403,
    ManagementErrorCode.ORIGIN_DENIED: 403,
    ManagementErrorCode.RESOURCE_NOT_FOUND: 404,
    ManagementErrorCode.OPERATION_NOT_FOUND: 404,
    ManagementErrorCode.RESOURCE_CONFLICT: 409,
    ManagementErrorCode.IDENTITY_CONFLICT: 409,
    ManagementErrorCode.REVISION_CONFLICT: 409,
    ManagementErrorCode.STATE_CONFLICT: 409,
    ManagementErrorCode.VALIDATION_FAILED: 422,
    ManagementErrorCode.UNSUPPORTED_VALUE: 422,
    ManagementErrorCode.RATE_LIMITED: 429,
    ManagementErrorCode.OPERATION_ALREADY_RUNNING: 429,
    ManagementErrorCode.UPSTREAM_ERROR: 502,
    ManagementErrorCode.SERVICE_NOT_READY: 503,
    ManagementErrorCode.DEPENDENCY_UNAVAILABLE: 503,
    ManagementErrorCode.UPSTREAM_TIMEOUT: 504,
})


def _error_example(code: ManagementErrorCode) -> dict:
    error = ManagementError(
        code,
        retryable=code
        in {
            ManagementErrorCode.RATE_LIMITED,
            ManagementErrorCode.OPERATION_ALREADY_RUNNING,
            ManagementErrorCode.SERVICE_NOT_READY,
            ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
            ManagementErrorCode.UPSTREAM_TIMEOUT,
        },
    )
    return {
        "error": {
            "code": code.value,
            "message": error.message,
            "fields": [],
            "retryable": error.retryable,
            "requestId": "request-example",
            "operationId": None,
        }
    }


def management_error_responses(
    *codes: ManagementErrorCode,
) -> dict[int, dict]:
    """Build reusable OpenAPI responses from the frozen error/status table."""
    grouped: dict[int, list[ManagementErrorCode]] = defaultdict(list)
    for code in codes:
        if not isinstance(code, ManagementErrorCode):
            raise TypeError("management error responses require ManagementErrorCode values")
        grouped[MANAGEMENT_ERROR_STATUS[code]].append(code)
    return {
        status: {
            "model": ErrorEnvelope,
            "description": "Management API error: "
            + ", ".join(code.value for code in status_codes),
            "content": {
                "application/json": {
                    "examples": {
                        code.value: {
                            "summary": code.value,
                            "value": _error_example(code),
                        }
                        for code in status_codes
                    }
                }
            },
        }
        for status, status_codes in grouped.items()
    }


def error_response(error: ManagementError, *, request_id: str) -> JSONResponse:
    response = JSONResponse(
        status_code=MANAGEMENT_ERROR_STATUS[error.code],
        content={
            "error": {
                "code": error.code.value,
                "message": error.message,
                "fields": [
                    {"path": item.path, "code": item.code, "message": item.message}
                    for item in error.fields
                ],
                "retryable": error.retryable,
                "requestId": request_id,
                "operationId": error.operation_id,
            }
        },
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Request-Id"] = request_id
    return response


async def _management_error_handler(request: Request, exc: ManagementError) -> JSONResponse:
    return error_response(exc, request_id=management_request_id(request))


def _field_path(location: tuple | list) -> str:
    parts = [str(item) for item in location if item not in {"body", "query", "path", "header"}]
    path = ""
    for part in parts:
        if part.isdigit():
            path += f"[{part}]"
        else:
            path += ("." if path else "") + part
    return path or "request"


async def _validation_error_handler(request: Request, exc: RequestValidationError):
    if not is_management_path(request.url.path):
        return await request_validation_exception_handler(request, exc)
    fields = tuple(
        ErrorField(
            path=_field_path(item.get("loc") or ()),
            code=str(item.get("type") or "invalid"),
            message=str(item.get("msg") or "Invalid value"),
        )
        for item in exc.errors()
    )
    error = ManagementError(
        ManagementErrorCode.VALIDATION_FAILED,
        fields=fields,
    )
    return error_response(error, request_id=management_request_id(request))


def install_management_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ManagementError, _management_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)

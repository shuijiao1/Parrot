"""Strict query-parameter validation shared only by P5 HTTP adapters."""

from __future__ import annotations

from collections.abc import Collection

from fastapi import Request

from src.management_control import ErrorField, ManagementError, ManagementErrorCode


def reject_unknown_query_parameters(
    request: Request,
    allowed: Collection[str] = (),
) -> None:
    """Reject undeclared query keys instead of letting FastAPI ignore them."""
    unknown = sorted(set(request.query_params) - set(allowed))
    if not unknown:
        return
    raise ManagementError(
        ManagementErrorCode.VALIDATION_FAILED,
        fields=tuple(
            ErrorField(
                path=name,
                code="UNKNOWN_QUERY_PARAMETER",
                message=f"query parameter {name!r} is not supported",
            )
            for name in unknown
        ),
    )

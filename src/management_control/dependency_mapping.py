"""Shared dependency-failure translation for Management controls."""

from __future__ import annotations

from typing import Callable, TypeVar

from .errors import ManagementError, ManagementErrorCode


_Result = TypeVar("_Result")


def dependency_result(callable_: Callable[[], _Result]) -> _Result:
    """Return a dependency result without retaining a raw failure chain."""
    failed = False
    try:
        value = callable_()
    except Exception:
        failed = True
    if failed:
        raise ManagementError(
            ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
        )
    return value

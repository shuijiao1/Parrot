"""Narrow error translation for Management reads of retained log databases."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from src import log_db as log_db_module
from src.management_control.errors import ManagementError, ManagementErrorCode


@contextmanager
def map_historical_log_errors() -> Iterator[None]:
    """Expose historical log failures through the stable Management contract."""

    try:
        yield
    except log_db_module.HistoricalLogError as exc:
        raise ManagementError(
            ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
            retryable=True,
        ) from exc

"""Shared transport-neutral primitives for observability controls."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, Iterable, TypeVar

from src.management_auth import (
    AuthMethod,
    Capability,
    CapabilityDenied,
    ManagementPrincipal,
    authorize,
)
from src.management_control.context import ManagementContext
from src.management_control.public_safety import redact_known_fields
from src.management_control.errors import ErrorField, ManagementError, ManagementErrorCode


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PageResult(Generic[T]):
    items: tuple[T, ...]
    page: int
    page_size: int
    total: int

    @property
    def has_next(self) -> bool:
        return self.page * self.page_size < self.total


class SortDirection(str, Enum):
    ASC = "asc"
    DESC = "desc"


def require(context: ManagementContext, capability: Capability = Capability.READ) -> None:
    """Apply the common policy at the control boundary."""
    try:
        authorize(context.actor, capability)
    except CapabilityDenied as exc:
        raise ManagementError(ManagementErrorCode.CAPABILITY_DENIED) from exc


def telegram_context(subject: str = "telegram-admin") -> ManagementContext:
    """Build the transport-neutral actor used by an already-authorized TG adapter."""
    return ManagementContext(
        request_id=f"tg:{subject}",
        actor=ManagementPrincipal.administrator(
            subject_id=subject,
            auth_method=AuthMethod.TELEGRAM_ADMIN,
            session_id=None,
        ),
    )


def revision_for(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return "rev_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def utc_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            try:
                dt = datetime.fromtimestamp(float(text), tz=timezone.utc)
            except (TypeError, ValueError, OverflowError):
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_utc_range(
    started_at: datetime | None,
    ended_at: datetime | None,
) -> tuple[datetime | None, datetime | None]:
    """Validate typed API bounds and normalize aware values to UTC.

    Storage timestamps remain backward compatible through :func:`utc_datetime`,
    but public query bounds must never silently assign a timezone to a naive
    value.  Keeping this check in the control package also protects non-HTTP
    adapters and direct callers from bare aware/naive ``TypeError`` failures.
    """
    normalized: list[datetime | None] = []
    for path, value in (("startedAt", started_at), ("endedAt", ended_at)):
        if value is None:
            normalized.append(None)
            continue
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise validation_error(path, "timezone_required", "RFC 3339 timezone offset is required")
        try:
            offset = value.utcoffset()
        except (TypeError, ValueError, OverflowError) as exc:
            raise validation_error(path, "invalid_datetime", "Invalid RFC 3339 timestamp") from exc
        if offset is None:
            raise validation_error(path, "timezone_required", "RFC 3339 timezone offset is required")
        try:
            normalized.append(value.astimezone(timezone.utc))
        except (TypeError, ValueError, OverflowError) as exc:
            raise validation_error(path, "invalid_datetime", "Invalid RFC 3339 timestamp") from exc
    start, end = normalized
    if start is not None and end is not None and start > end:
        raise validation_error("endedAt", "invalid_range", "endedAt must not precede startedAt")
    return start, end


def page_slice(items: Iterable[T], *, page: int, page_size: int) -> PageResult[T]:
    values = tuple(items)
    start = (page - 1) * page_size
    return PageResult(values[start:start + page_size], page, page_size, len(values))


def _camel_key(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def camelize(value: Any) -> Any:
    """Convert control-owned machine keys to the v1 JSON naming convention."""
    if isinstance(value, dict):
        return {_camel_key(str(key)): camelize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [camelize(item) for item in value]
    if isinstance(value, tuple):
        return [camelize(item) for item in value]
    return copy.deepcopy(value)


def sanitize_credentials(value: Any) -> Any:
    """Redact only explicit secret fields in actual structured values.

    Ordinary strings are returned unchanged; this function does not parse JSON or
    search prose for credential- or URL-shaped fragments.
    """
    return redact_known_fields(value, replacement="<redacted>")


def validation_error(path: str, code: str, message: str) -> ManagementError:
    return ManagementError(
        ManagementErrorCode.VALIDATION_FAILED,
        fields=(ErrorField(path=path, code=code, message=message),),
    )

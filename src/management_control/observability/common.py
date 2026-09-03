"""Shared transport-neutral primitives for observability controls."""

from __future__ import annotations

import copy
import hashlib
import json
import re
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


def page_slice(items: Iterable[T], *, page: int, page_size: int) -> PageResult[T]:
    values = tuple(items)
    start = (page - 1) * page_size
    return PageResult(values[start:start + page_size], page, page_size, len(values))


_SECRET_KEYS = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey",
    "api_key", "access_token", "refreshtoken", "refresh_token", "id_token",
    "managementkey", "management_key", "session", "session_token", "password",
    "client_secret", "bot_token", "cookie", "set-cookie",
}
_SECRET_KEYS_COMPACT = {
    key.lower().replace(" ", "").replace("-", "").replace("_", "")
    for key in _SECRET_KEYS
}


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
    """Recursively remove credentials while preserving authorized business body data."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace(" ", "").replace("-", "_")
            compact = normalized.replace("_", "")
            if normalized in _SECRET_KEYS or compact in _SECRET_KEYS_COMPACT:
                out[str(key)] = "<redacted>"
            else:
                out[str(key)] = sanitize_credentials(item)
        return out
    if isinstance(value, list):
        return [sanitize_credentials(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_credentials(item) for item in value)
    if isinstance(value, str):
        lowered = value.lower().strip()
        if lowered.startswith("bearer ") or lowered.startswith("basic "):
            return value.split(" ", 1)[0] + " <redacted>"
        value = re.sub(
            r"(?i)\b(authorization|proxy-authorization|x-api-key|api[-_]?key|"
            r"access[_-]?token|refresh[_-]?token|password|client[_-]?secret)"
            r"(\s*[:=]\s*)(?:bearer\s+|basic\s+)?[^\s,;\"']+",
            lambda match: match.group(1) + match.group(2) + "<redacted>",
            value,
        )
        value = re.sub(
            r"(?i)([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@/\s]+(@)",
            r"\1<redacted>\2",
            value,
        )
        return value
    return copy.deepcopy(value)


def validation_error(path: str, code: str, message: str) -> ManagementError:
    return ManagementError(
        ManagementErrorCode.VALIDATION_FAILED,
        fields=(ErrorField(path=path, code=code, message=message),),
    )

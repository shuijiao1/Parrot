"""Shared transport-neutral primitives for observability controls."""

from __future__ import annotations

import base64
import binascii
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


_SECRET_KEY_TERMS = frozenset({"token", "key", "secret", "credential"})
_SECRET_KEYS = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey",
    "api_token", "access_token", "refresh_token", "id_token", "credential",
    "management_key", "management_token", "bot_key", "bot_token", "github_key",
    "github_token", "client_secret", "exchange_secret", "challenge_secret",
    "session", "session_token", "session_secret", "password", "passwd", "cookie",
    "set-cookie",
}
_SECRET_KEYS_COMPACT = {
    key.lower().replace(" ", "").replace("-", "").replace("_", "")
    for key in _SECRET_KEYS
}
_SPACED_SECRET_KEY_PATTERN = (
    r"proxy[ \t]+authorization|x[ \t]+api[ \t]+key|"
    r"(?:api|management|bot|github)[ \t]+(?:key|token)|"
    r"(?:access|refresh|id)[ \t]+token|"
    r"(?:client|exchange|challenge)[ \t]+secret|"
    r"session[ \t]+(?:token|secret)|set[ \t]+cookie"
)
_SECRET_VALUE_PATTERN = (
    r'\\+"(?:\\.|[^"\\])*\\+"'
    r"|\\+'(?:\\.|[^'\\])*\\+'"
    r'|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r'|[^\s,;&}\]"\']+'
)
_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?<![\w-])(?P<key>(?:{_SPACED_SECRET_KEY_PATTERN})|[A-Za-z][A-Za-z0-9_-]*)"
    r"(?P<key_quote>(?:\\+[\"']|[\"'])?)(?P<separator>\s*[:=]\s*)"
    r"(?P<auth_prefix>(?:bearer\s+|basic\s+))?"
    rf"(?P<value>{_SECRET_VALUE_PATTERN})",
    re.IGNORECASE,
)
_STANDALONE_AUTH_RE = re.compile(
    r"(?<![\w-])(?P<scheme>Bearer|Basic)(?P<separator>[ \t]+)"
    r"(?P<value>[A-Za-z0-9._~+/=-]+)",
    re.IGNORECASE,
)
_URL_USERINFO_RE = re.compile(
    r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)[^/?#\s]+@",
    re.IGNORECASE,
)


def _is_secret_key(raw_key: str) -> bool:
    """Classify credential fields by a visible word boundary, not a suffix substring."""
    key = raw_key.strip()
    folded = key.casefold()
    compact = re.sub(r"[\s_-]+", "", folded)
    if folded in _SECRET_KEY_TERMS or compact in _SECRET_KEYS_COMPACT:
        return True

    parts = [part for part in re.split(r"[\s_-]+", key) if part]
    if len(parts) > 1 and parts[-1].casefold() in _SECRET_KEY_TERMS:
        return any(any(char.isalnum() for char in part) for part in parts[:-1])

    for term in _SECRET_KEY_TERMS:
        if len(key) <= len(term) or not folded.endswith(term):
            continue
        boundary = len(key) - len(term)
        suffix = key[boundary:]
        prefix = key[:boundary]
        if not suffix[0].isupper():
            continue
        if key[boundary - 1].islower() or key[boundary - 1].isdigit():
            return True
        if suffix == term.title() and prefix.isupper():
            return True
    return False


def _redacted_value(raw_value: str) -> str:
    for quote in ('"', "'"):
        if not raw_value.endswith(quote):
            continue
        opening_quote = raw_value.find(quote)
        if opening_quote < 0 or raw_value[:opening_quote].strip("\\"):
            continue
        closing_start = len(raw_value) - 1
        while closing_start > opening_quote and raw_value[closing_start - 1] == "\\":
            closing_start -= 1
        return raw_value[:opening_quote + 1] + "<redacted>" + raw_value[closing_start:]
    return "<redacted>"


def _redact_secret_assignment(match: re.Match[str]) -> str:
    if not _is_secret_key(match.group("key")):
        auth_prefix = match.group("auth_prefix") or ""
        raw_value = auth_prefix + match.group("value")
        clean_value = sanitize_credentials(raw_value)
        if clean_value == raw_value:
            return match.group(0)
        value_start = "auth_prefix" if auth_prefix else "value"
        value_offset = match.start(value_start) - match.start()
        return match.group(0)[:value_offset] + clean_value
    return (
        match.group("key") + match.group("key_quote") + match.group("separator")
        + _redacted_value(match.group("value"))
    )


def _looks_like_opaque_token(value: str) -> bool:
    if len(value) < 8:
        return False
    if not value.isalpha():
        return True
    if any(char.isupper() for char in value[1:]) and len(value) >= 12:
        return True
    return len(value) >= 24


def _is_auth_credential(scheme: str, value: str) -> bool:
    if "marker" in value.casefold():
        return True
    if scheme.casefold() == "basic":
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) is not None:
            try:
                decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
            except (binascii.Error, ValueError):
                decoded = b""
            if b":" in decoded:
                return True
        return _looks_like_opaque_token(value)

    if len(value) >= 8 and value.count(".") >= 2 and all(value.split(".")):
        return True
    return _looks_like_opaque_token(value)


def _redact_standalone_auth(match: re.Match[str]) -> str:
    if not _is_auth_credential(match.group("scheme"), match.group("value")):
        return match.group(0)
    return match.group("scheme") + match.group("separator") + "<redacted>"


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
            if _is_secret_key(str(key)):
                out[str(key)] = "<redacted>"
            else:
                out[str(key)] = sanitize_credentials(item)
        return out
    if isinstance(value, list):
        return [sanitize_credentials(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_credentials(item) for item in value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, (dict, list, str)):
            clean = sanitize_credentials(parsed)
            if clean != parsed:
                return json.dumps(clean, ensure_ascii=False, separators=(",", ":"))
        value = _SECRET_ASSIGNMENT_RE.sub(_redact_secret_assignment, value)
        value = _STANDALONE_AUTH_RE.sub(_redact_standalone_auth, value)
        return _URL_USERINFO_RE.sub(r"\g<scheme>", value)
    return copy.deepcopy(value)


def validation_error(path: str, code: str, message: str) -> ManagementError:
    return ManagementError(
        ManagementErrorCode.VALIDATION_FAILED,
        fields=(ErrorField(path=path, code=code, message=message),),
    )

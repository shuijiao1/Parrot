"""Shared, transport-neutral helpers for auxiliary management controls."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

from src import config
from src.management_auth.policy import CapabilityDenied, authorize
from src.management_auth.principal import AuthMethod, Capability, ManagementPrincipal

from ..context import AuditSink, ManagementContext, audit_record
from ..errors import ErrorField, ManagementError, ManagementErrorCode


class ConfigGateway(Protocol):
    def get(self) -> dict[str, Any]: ...
    def update(self, mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]: ...


class ModuleConfigGateway:
    """Narrow adapter around the application's atomic config boundary."""

    def get(self) -> dict[str, Any]:
        return config.get()

    def update(self, mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        return config.update(mutator)


def public_value(value: Any) -> Any:
    """Convert DTO/config values into a deterministic JSON-compatible value."""

    if is_dataclass(value):
        return public_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): public_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [public_value(item) for item in value]
    return value


def revision_for(value: Any) -> str:
    payload = json.dumps(
        public_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "rev_" + hashlib.sha256(payload).hexdigest()[:24]


def require(context: ManagementContext, *capabilities: Capability) -> None:
    for capability in capabilities:
        try:
            authorize(context.actor, capability)
        except CapabilityDenied as exc:
            raise ManagementError(ManagementErrorCode.CAPABILITY_DENIED) from exc


def ensure_revision(expected_revision: str | None, current_revision: str) -> None:
    if expected_revision is not None and expected_revision != current_revision:
        raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)


def invalid_field(path: str, code: str, message: str) -> ManagementError:
    return ManagementError(
        ManagementErrorCode.VALIDATION_FAILED,
        fields=(ErrorField(path=path, code=code, message=message),),
    )


def audit(
    sink: AuditSink | None,
    context: ManagementContext,
    *,
    action: str,
    target: str,
    result: str = "succeeded",
) -> None:
    if sink is not None:
        sink.record(audit_record(context, action=action, target=target, result=result))


def telegram_context(chat_id: int) -> ManagementContext:
    """Build the principal already authenticated by Telegram's admin adapter."""

    return ManagementContext(
        request_id=f"telegram:{chat_id}",
        actor=ManagementPrincipal.administrator(
            subject_id=f"telegram-admin:{chat_id}",
            auth_method=AuthMethod.TELEGRAM_ADMIN,
            issued_at=datetime.now(timezone.utc),
        ),
    )


def rfc3339_utc(value: Any, *, compact: bool = False) -> str | None:
    """Normalize a supported production timestamp without echoing invalid input."""

    parsed: datetime | None = None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            seconds = float(value)
            if math.isfinite(seconds):
                parsed = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            parsed = None
    elif isinstance(value, str):
        raw = value.strip()
        if raw:
            if compact:
                try:
                    parsed = datetime.strptime(raw, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    parsed = None
            if parsed is None and re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", raw):
                try:
                    seconds = float(raw)
                    if math.isfinite(seconds):
                        parsed = datetime.fromtimestamp(seconds, tz=timezone.utc)
                except (OverflowError, OSError, ValueError):
                    parsed = None
            if parsed is None and re.search(r"[Tt ]\d{2}:?\d{2}", raw):
                iso_value = raw[:-1] + "+00:00" if raw[-1:] in {"Z", "z"} else raw
                try:
                    parsed = datetime.fromisoformat(iso_value)
                except ValueError:
                    parsed = None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value:
        normalized = str(item or "").strip()
        if normalized and normalized not in result:
            result.append(normalized)
    return result

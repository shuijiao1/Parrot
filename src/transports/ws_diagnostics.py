"""Bounded WS-close diagnostics, separate from client errors and failure policy.

Only close metadata and typed exception facts are recorded. Never log frames,
headers, exception arguments/tracebacks, or SS key/ciphertext material.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import quote

logger = logging.getLogger(__name__)
_CREDENTIAL_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
    "chatgpt-account-id", "x-account-id",
})
_CREDENTIAL_PAIR = re.compile(
    r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|"
    r"managementkey|password|passwd|secret|token|authorization|cookie)"
    r"[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+[^\s,;]+")


def _known_credentials(ws) -> tuple[str, ...]:
    """Use the actual handshake header values only for exact-value redaction.

    They remain on the WS owner and are never copied into timing or diagnostics.
    This also works for a reused connection's later request/round.
    """
    headers = getattr(getattr(ws, "request", None), "headers", None)
    if headers is None:
        return ()
    raw_items = getattr(headers, "raw_items", None)
    items = raw_items() if callable(raw_items) else headers.items()
    values: set[str] = set()
    for name, value in items:
        if str(name).lower() not in _CREDENTIAL_HEADERS or not isinstance(value, str) or not value:
            continue
        values.add(value)
        if str(name).lower() in {"authorization", "proxy-authorization"}:
            parts = value.split(None, 1)
            if len(parts) == 2:
                values.add(parts[1])
        if str(name).lower() == "cookie":
            for cookie in value.split(";"):
                _, separator, token = cookie.partition("=")
                if separator and token.strip():
                    values.add(token.strip())
    values.update(quote(value, safe="") for value in tuple(values))
    return tuple(sorted(values, key=len, reverse=True))


def _text(value: Any, secrets: tuple[str, ...], limit: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    # Redact BEFORE truncation, otherwise a truncated credential could escape.
    for secret in secrets:
        value = value.replace(secret, "<redacted>")
    value = _AUTH_VALUE.sub(lambda m: m.group(1) + " <redacted>", value)
    value = _CREDENTIAL_PAIR.sub(lambda m: m.group(1) + "<redacted>", value)
    return value.replace("\r", " ").replace("\n", " ")[:limit]


def _integer(value: Any) -> int | None:
    # Sent Close frames use websockets.frames.CloseCode (an IntEnum).
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None


def _exceptions(exc: BaseException | None) -> list[dict[str, Any]]:
    result = []
    seen: set[int] = set()
    while isinstance(exc, BaseException) and id(exc) not in seen and len(result) < 3:
        seen.add(id(exc))
        result.append({
            "type": type(exc).__name__[:100],
            "module": type(exc).__module__[:100],
            "errno": _integer(getattr(exc, "errno", None)),
        })
        exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    return result


def _close(frame, secrets: tuple[str, ...]) -> dict[str, Any] | None:
    if frame is None:
        return None
    return {"code": _integer(getattr(frame, "code", None)),
            "reason": _text(getattr(frame, "reason", None), secrets)}


def _local_keepalive_timeout(exc) -> bool | None:
    sent = getattr(exc, "sent", None)
    if sent is None or getattr(sent, "code", None) != 1011 or getattr(sent, "reason", None) != "keepalive ping timeout":
        return False
    received = getattr(exc, "rcvd", None)
    order = getattr(exc, "rcvd_then_sent", None)
    if received is None or order is False:
        return True
    # Echoing a peer's keepalive-timeout close isn't a local heartbeat timeout.
    return False if order is True else None


def log_ws_close(ws, tracker, exc: BaseException, *, phase: str, timing=None) -> None:
    """Best-effort, once-per-round snapshot before caller-owned cleanup.

    Normal terminal closure is silent. No outcome, retry, timeout, close or
    client-facing error value is changed here, even if diagnostics fail.
    """
    try:
        if any(bool(getattr(tracker, field, False)) for field in (
            "response_completed", "response_failed", "response_incomplete",
        )):
            return
        if timing is not None and getattr(timing, "_ws_close_diagnostic_logged", False):
            return
        secrets = _known_credentials(ws)
        event = getattr(tracker, "last_event", None)
        snapshot = timing.snapshot(terminal=True) if timing is not None else None
        order = getattr(exc, "rcvd_then_sent", None)
        bridge = getattr(ws, "bridge", None)
        terminal = getattr(bridge, "terminal", None) if bridge is not None else None
        read_end = getattr(bridge, "read_termination", None) if bridge is not None else None
        ss = None
        if bridge is not None:
            ss = {
                "direction": _text(getattr(terminal, "direction", None), secrets, 100),
                "graceful": getattr(terminal, "graceful", None) if terminal is not None else None,
                "exceptions": _exceptions(getattr(terminal, "cause", None)),
                "read_termination": None if read_end is None else {
                    "phase": _text(getattr(read_end, "phase", None), secrets, 50),
                    "error_type": _text(getattr(read_end, "error_type", None), secrets, 100),
                    "error_module": _text(getattr(read_end, "error_module", None), secrets, 100),
                    "errno": _integer(getattr(read_end, "errno", None)),
                    "expected_bytes": _integer(getattr(read_end, "expected_bytes", None)),
                    "partial_bytes": _integer(getattr(read_end, "partial_bytes", None)),
                },
            }
        payload = {
            "event": "upstream_ws_closed", "version": 1,
            "phase": phase,
            "request_id": _text(getattr(timing, "diagnostic_request_id", None), secrets, 160),
            "round_id": _text(getattr(timing, "round_id", None), secrets, 160),
            "proxy_name": _text(getattr(timing, "diagnostic_proxy_name", None), secrets, 128),
            "route_type": _text(getattr(timing, "route_type", None), secrets, 50),
            "last_event_type": _text(event.get("type"), secrets, 128) if isinstance(event, dict) else None,
            "round_total_ms": _integer(getattr(snapshot, "total_ms", None)),
            "idle_ms": _integer(getattr(snapshot, "idle_ms", None)),
            "ws": {
                "received": _close(getattr(exc, "rcvd", None), secrets),
                "sent": _close(getattr(exc, "sent", None), secrets),
                "received_then_sent": order if type(order) is bool else None,
                "local_keepalive_timeout": _local_keepalive_timeout(exc),
                "exceptions": _exceptions(exc),
            },
            "ss_bridge": ss,
        }
        logger.warning("[ws-close-diagnostic] %s", json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
        if timing is not None:
            timing._ws_close_diagnostic_logged = True
    except Exception:
        # Diagnostics are observational and must never break the request path.
        return

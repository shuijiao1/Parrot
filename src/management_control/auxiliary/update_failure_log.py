"""Narrow API-only masking for update failure logs.

The Telegram adapter deliberately reads the gateway's raw log instead.  This
module handles only explicit key/value fields and URL userinfo; it is not a
free-text credential classifier.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


_REDACTION = "***"
# Exact names used by update/config/provider command diagnostics.  A value is
# masked only when the name is followed by structured ``:``/``=`` syntax.
_SECRET_FIELD = re.compile(
    r"(?P<prefix>"
    r"(?<![A-Za-z0-9_])"
    r"(?:\"(?:access_token|refresh_token|api_token|api_key|apiKey|password|proxyPassword|credential)\""
    r"|'(?:access_token|refresh_token|api_token|api_key|apiKey|password|proxyPassword|credential)'"
    r"|(?:access_token|refresh_token|api_token|api_key|apiKey|password|proxyPassword|credential))"
    r"\s*[:=]\s*"
    r")"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,}\]\r\n]+)",
)
_URL = re.compile(r"(?P<url>(?P<scheme>https?|ssh)://[^\s<>\"']+)", re.IGNORECASE)


def _mask_field(match: re.Match[str]) -> str:
    value = match.group("value")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
        masked = f"{value[0]}{_REDACTION}{value[0]}"
    else:
        masked = _REDACTION
    return f"{match.group('prefix')}{masked}"


def _mask_url(match: re.Match[str]) -> str:
    raw = match.group("url")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw
    if "@" not in parsed.netloc:
        return raw
    userinfo, host = parsed.netloc.rsplit("@", 1)
    if not userinfo or not host:
        return raw
    masked = f"{_REDACTION}:{_REDACTION}" if ":" in userinfo else _REDACTION
    return urlunsplit(parsed._replace(scheme=match.group("scheme"), netloc=f"{masked}@{host}"))


def sanitize_update_failure_log(value: str, *, max_chars: int = 3500) -> str:
    """Mask only known structured secrets and parsed URL userinfo for the API."""
    text = str(value or "")
    text = _SECRET_FIELD.sub(_mask_field, text)
    text = _URL.sub(_mask_url, text)
    return text[-max_chars:]

"""Explicit structured-field and URL projections for network management."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.management_control.public_safety import (
    is_known_sensitive_field,
    redact_known_fields,
    split_public_url,
    without_url_userinfo,
)


def sanitize_public_network_text(value: Any) -> str:
    """Return ordinary network labels, details and error prose unchanged."""
    return str(value)


def sanitize_public_network(value: Any) -> Any:
    """Redact only known fields in an actual structured network value."""
    return redact_known_fields(value, replacement="<redacted>")


def safe_network_url(
    value: str, *, mask_user: bool = False, drop_path: bool = False,
) -> str:
    """Project one known URL, handling userinfo and known secret query fields."""
    raw = str(value or "")
    try:
        parsed = split_public_url(raw)
        if not parsed.scheme or not parsed.hostname:
            return ""
        clean = without_url_userinfo(
            raw, masked_userinfo="***:***" if mask_user else None,
        )
        parsed = urlsplit(clean)
        if drop_path:
            return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        query = [
            (key, "[REDACTED]" if is_known_sensitive_field(key) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""),
        )
    except (TypeError, ValueError):
        return ""


def safe_dns_server(value: Any) -> str:
    raw = str(value or "")
    return safe_network_url(raw) if "://" in raw else raw

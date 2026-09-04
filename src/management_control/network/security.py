"""Credential-safe public projections for the network management control."""

from __future__ import annotations

import base64
import copy
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.management_control.observability.common import sanitize_credentials


MONITOR_PUBLIC_IDENTIFIER_KEYS = frozenset({
    "key", "category", "channelKey", "keyId", "keyCount",
})
_AUTH_SCHEME_RE = re.compile(
    r"(?P<prefix>\b(?P<scheme>bearer|basic)\s+)"
    r"(?:(?P<quote>\\*[\"'])(?P<quoted>.*?)(?P=quote)|"
    r"(?P<bare>(?!\[REDACTED\])[^\s\\\"',;&}\]]+))",
    re.IGNORECASE,
)
_KEY_CLASSIFIER_SENTINEL = "p6-network-public-value"


def _looks_like_auth_credential(scheme: str, candidate: str) -> bool:
    if not candidate or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", candidate):
        return False
    marker_parts = {
        part for part in re.split(r"[^a-z0-9]+", candidate.casefold()) if part
    }
    if marker_parts & {"token", "key", "secret", "credential", "marker"}:
        return True
    if scheme.casefold() == "basic" and len(candidate) >= 8:
        try:
            decoded = base64.b64decode(
                candidate + "=" * (-len(candidate) % 4), altchars=b"-_", validate=True,
            )
        except (ValueError, TypeError):
            decoded = b""
        if b":" in decoded:
            return True
    punctuation_count = sum(not char.isalnum() for char in candidate)
    return (
        (any(char.isdigit() for char in candidate) and len(candidate) >= 8)
        or (punctuation_count >= 2 and len(candidate) >= 8)
        or (bool(punctuation_count) and len(candidate) >= 16)
        or (candidate.isalpha() and len(candidate) >= 24)
        or (
            candidate.lower() != candidate
            and candidate.upper() != candidate
            and len(candidate) >= 16
        )
    )


def sanitize_public_network_text(value: Any) -> str:
    """Redact secrets while preserving ordinary Bearer/Basic prose exactly."""
    raw = str(value)
    preserved: dict[str, str] = {}

    def replace_auth(match: re.Match[str]) -> str:
        quote = match.group("quote") or ""
        candidate = match.group("quoted") or match.group("bare") or ""
        stripped = candidate if quote else candidate.rstrip(".,!?)")
        trailing = candidate[len(stripped):]
        if _looks_like_auth_credential(match.group("scheme"), stripped):
            return match.group("prefix") + quote + "<redacted>" + quote + trailing
        placeholder = f"\0PUBLICAUTH{len(preserved)}\0"
        while placeholder in raw:
            placeholder += "\0"
        preserved[placeholder] = match.group(0)
        return placeholder

    clean = str(sanitize_credentials(_AUTH_SCHEME_RE.sub(replace_auth, raw)))
    for placeholder, text in preserved.items():
        clean = clean.replace(placeholder, text)
    return clean


def _is_secret_key(key: str) -> bool:
    classified = sanitize_credentials({key: _KEY_CLASSIFIER_SENTINEL})
    return classified.get(key) != _KEY_CLASSIFIER_SENTINEL


def sanitize_public_network(
    value: Any, *, public_identifier_keys: frozenset[str] = frozenset(),
) -> Any:
    """Sanitize recursively; identifier exceptions apply only to this level."""
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if key not in public_identifier_keys and _is_secret_key(key):
                clean[key] = "<redacted>"
            else:
                clean[key] = sanitize_public_network(item)
        return clean
    if isinstance(value, list):
        return [sanitize_public_network(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_public_network(item) for item in value)
    if isinstance(value, str):
        return sanitize_public_network_text(value)
    return copy.deepcopy(value)


def safe_network_url(
    value: str, *, mask_user: bool = False, drop_path: bool = False,
) -> str:
    """Project a network URL without userinfo or credential-named query values."""
    raw = str(value or "")
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return sanitize_public_network_text(raw)
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        if mask_user and (parsed.username is not None or parsed.password is not None):
            netloc = "***:***@" + netloc
        query = []
        if not drop_path:
            for key, item in parse_qsl(parsed.query, keep_blank_values=True):
                cleaned = sanitize_public_network({key: item}).get(key)
                query.append((key, "[REDACTED]" if cleaned != item else item))
        result = urlunsplit(
            (parsed.scheme, netloc, "" if drop_path else parsed.path, urlencode(query), ""),
        )
        # Explicitly masked userinfo is already safe and must remain visible as
        # the stable client placeholder rather than being removed as userinfo.
        return result if mask_user else sanitize_public_network_text(result)
    except Exception:
        return sanitize_public_network_text(raw)


def safe_dns_server(value: Any) -> str:
    raw = str(value or "")
    return safe_network_url(raw) if "://" in raw else sanitize_public_network_text(raw)

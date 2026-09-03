"""Credential-safe URL and error text handling for the Channels API boundary."""

from __future__ import annotations

import re
from urllib.parse import SplitResult, urlsplit, urlunsplit


_REDACTED = "[REDACTED]"
_URL_USERINFO = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.-]*:(?:[\\]*/){2})[^/@\s\"']+@",
    re.IGNORECASE,
)
_CREDENTIAL_KEYS = (
    r"(?:x[-_]?api[-_]?key|api[-_]?(?:token|key)|access[-_]?token|"
    r"refresh[-_]?token|id[-_]?token|management[-_]?key|bot[-_]?token|"
    r"github[-_]?token|client[-_]?secret|session(?:[-_]?token)?|password|"
    r"passwd|set[-_]?cookie|cookie)"
)
_AUTHORIZATION_KEYS = r"(?:proxy[-_]?authorization|authorization)"
_QUOTED_VALUE = r"(?P<quote>\\*[\"'])(?P<quoted>.*?)(?P=quote)"
_BARE_VALUE = r"(?P<bare>(?!\[REDACTED\])[^\s\\\"',;&}\]]+)"
_KEY_ASSIGNMENT = re.compile(
    rf"(?P<prefix>\b{_CREDENTIAL_KEYS}\b(?:\\*[\"'])?\s*(?:=|:)\s*)"
    rf"(?:{_QUOTED_VALUE}|{_BARE_VALUE})",
    re.IGNORECASE,
)
_AUTHORIZATION = re.compile(
    rf"(?P<prefix>\b{_AUTHORIZATION_KEYS}\b(?:\\*[\"'])?\s*(?:=|:)\s*)"
    rf"(?:"
    rf"(?P<quote>\\*[\"'])(?P<quoted_scheme>(?:bearer|basic)\s+)?"
    rf"(?P<quoted>.*?)(?P=quote)|"
    rf"(?P<bare_scheme>(?:bearer|basic)\s+)?{_BARE_VALUE}"
    rf")",
    re.IGNORECASE,
)
_AUTH_SCHEME = re.compile(
    rf"(?P<prefix>\b(?:bearer|basic)\s+)(?:{_QUOTED_VALUE}|{_BARE_VALUE})",
    re.IGNORECASE,
)


def _parse_url(value: str) -> SplitResult:
    parsed = urlsplit(value)
    # These properties perform validation that urlsplit otherwise defers.
    _ = parsed.hostname, parsed.port, parsed.username, parsed.password
    return parsed


def require_url_without_userinfo(value: str) -> str:
    """Pydantic validator that rejects credentials without echoing the input."""
    try:
        parsed = _parse_url(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("URL could not be safely parsed") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL userinfo is not allowed")
    # A malformed authority-like value must not bypass userinfo detection.
    if not parsed.netloc and "@" in parsed.path:
        raise ValueError("URL could not be safely parsed")
    return value


def strip_url_userinfo(value: str) -> str:
    """Remove the whole userinfo component while preserving host, port and path."""
    try:
        parsed = _parse_url(value)
    except (TypeError, ValueError):
        return ""
    if not parsed.netloc:
        return "" if "@" in parsed.path else value
    if parsed.hostname is None:
        return ""
    if parsed.username is None and parsed.password is None:
        return value
    safe_netloc = parsed.netloc.rsplit("@", 1)[-1]
    if not safe_netloc:
        return ""
    return urlunsplit(parsed._replace(netloc=safe_netloc))


def _redact_match(match: re.Match[str]) -> str:
    groups = match.groupdict()
    quote = groups.get("quote") or ""
    scheme = groups.get("quoted_scheme") or groups.get("bare_scheme") or ""
    return match.group("prefix") + quote + scheme + _REDACTED + quote


def redact_credential_text(value: str | None) -> str | None:
    """Redact common credential forms from provider error text only."""
    if value is None:
        return None
    safe = _URL_USERINFO.sub(lambda match: match.group("prefix"), str(value))
    safe = _KEY_ASSIGNMENT.sub(_redact_match, safe)
    safe = _AUTHORIZATION.sub(_redact_match, safe)
    return _AUTH_SCHEME.sub(_redact_match, safe)

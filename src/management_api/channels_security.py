"""Credential-safe URL and error text handling for the Channels API boundary."""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit


_REDACTED = "[REDACTED]"
_URL_USERINFO = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.-]*:(?:[\\]*/){2})[^/@\s\"']+@",
    re.IGNORECASE,
)
_CREDENTIAL_TERMS = frozenset({"token", "key", "secret", "credential"})
# Concatenated lower-case aliases have no word boundary to classify. Keep the
# established aliases explicit; delimited, camel/Pascal and upper-case names
# are handled structurally by _is_credential_key.
_EXPLICIT_CREDENTIAL_KEYS = frozenset(
    {
        "xapikey",
        "apitoken",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "managementkey",
        "bottoken",
        "githubtoken",
        "clientsecret",
        "session",
        "sessiontoken",
        "sessionsecret",
        "exchangesecret",
        "exchangecredential",
        "challengesecret",
        "challengecredential",
        "password",
        "passwd",
        "setcookie",
        "cookie",
    }
)
_CAMEL_CREDENTIAL_SUFFIX = re.compile(r"(?:Token|Key|Secret|Credential)$")
_AUTHORIZATION_KEYS = r"(?:proxy[-_]?authorization|authorization)"
_QUOTED_VALUE = r"(?P<quote>\\*[\"'])(?P<quoted>.*?)(?P=quote)"
_BARE_VALUE = r"(?P<bare>(?!\[REDACTED\])[^\s\\\"',;&}\]]+)"
_KEY_ASSIGNMENT = re.compile(
    rf"(?P<prefix>\b(?P<key>[A-Za-z][A-Za-z0-9_-]*)\b"
    rf"(?:\\*[\"'])?\s*(?:=|:)\s*)(?:{_QUOTED_VALUE}|{_BARE_VALUE})",
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
    rf"(?P<prefix>\b(?P<scheme>bearer|basic)\s+)"
    rf"(?:{_QUOTED_VALUE}|{_BARE_VALUE})",
    re.IGNORECASE,
)
_AUTH_TOKEN_CHARS = re.compile(r"[A-Za-z0-9._~+/=-]+\Z")
_AUTH_TRAILING_PUNCTUATION = ".,!?)"


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


def _is_credential_key(key: str) -> bool:
    folded = key.casefold()
    normalized = folded.replace("-", "").replace("_", "")
    if folded in _CREDENTIAL_TERMS or normalized in _EXPLICIT_CREDENTIAL_KEYS:
        return True

    parts = tuple(part for part in re.split(r"[-_]", key) if part)
    if len(parts) > 1:
        return parts[-1].casefold() in _CREDENTIAL_TERMS

    if _CAMEL_CREDENTIAL_SUFFIX.search(key):
        return True

    # ALL_CAPS removes the lexical boundary before a suffix. A non-empty
    # prefix plus a credential term is the only structural signal available.
    if key.isupper():
        return any(
            folded.endswith(term) and len(folded) > len(term)
            for term in _CREDENTIAL_TERMS
        )
    return False


def _redact_match(match: re.Match[str]) -> str:
    groups = match.groupdict()
    quote = groups.get("quote") or ""
    scheme = groups.get("quoted_scheme") or groups.get("bare_scheme") or ""
    return match.group("prefix") + quote + scheme + _REDACTED + quote


def _redact_key_assignment(match: re.Match[str]) -> str:
    if not _is_credential_key(match.group("key")):
        return match.group(0)
    return _redact_match(match)


def _is_basic_base64_credential(candidate: str) -> bool:
    if len(candidate) < 8 or not _AUTH_TOKEN_CHARS.fullmatch(candidate):
        return False
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    return b":" in decoded


def _looks_like_auth_credential(scheme: str, candidate: str) -> bool:
    if not candidate or not _AUTH_TOKEN_CHARS.fullmatch(candidate):
        return False
    lowered = candidate.casefold()
    marker_parts = {part for part in re.split(r"[^a-z0-9]+", lowered) if part}
    if lowered == "marker" or marker_parts & (_CREDENTIAL_TERMS | {"marker"}):
        return True
    if scheme.casefold() == "basic" and _is_basic_base64_credential(candidate):
        return True

    punctuation_count = sum(not char.isalnum() for char in candidate)
    has_mixed_case = candidate.lower() != candidate and candidate.upper() != candidate
    if any(char.isdigit() for char in candidate) and len(candidate) >= 8:
        return True
    if punctuation_count >= 2 and len(candidate) >= 8:
        return True
    if punctuation_count and len(candidate) >= 16:
        return True
    if candidate.isalpha() and len(candidate) >= 24:
        return True
    return has_mixed_case and len(candidate) >= 16


def _redact_auth_scheme(match: re.Match[str]) -> str:
    groups = match.groupdict()
    quote = groups.get("quote") or ""
    candidate = groups.get("quoted") or groups.get("bare") or ""
    trailing = ""
    if not quote:
        stripped = candidate.rstrip(_AUTH_TRAILING_PUNCTUATION)
        trailing = candidate[len(stripped) :]
        candidate = stripped
    if not _looks_like_auth_credential(match.group("scheme"), candidate):
        return match.group(0)
    return match.group("prefix") + quote + _REDACTED + quote + trailing


def redact_credential_text(value: str | None) -> str | None:
    """Redact common credential forms from provider error text only."""
    if value is None:
        return None
    safe = _URL_USERINFO.sub(lambda match: match.group("prefix"), str(value))
    safe = _KEY_ASSIGNMENT.sub(_redact_key_assignment, safe)
    safe = _AUTHORIZATION.sub(_redact_match, safe)
    return _AUTH_SCHEME.sub(_redact_auth_scheme, safe)

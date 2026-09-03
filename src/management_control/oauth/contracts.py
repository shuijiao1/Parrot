"""Management-only OAuth contract helpers.

These helpers deliberately do not alter Telegram/raw domain values.  They are used
when typed Management API DTOs, plans, operations, and audit records are built.
"""

from __future__ import annotations

import base64
import copy
import functools
import hashlib
import inspect
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


_VOLATILE_CANDIDATE_FIELDS = {
    "last_refresh",
    "last_model_sync",
    "last_model_sync_attempt",
    "last_model_sync_error",
    "last_model_sync_source",
}
_SENSITIVE_KEY_WORDS = {
    "authorization", "cookie", "credential", "key", "passwd", "password",
    "secret", "session", "token",
}
_PUBLIC_KEY_NORMALIZED = {
    "accountkey",
    "channelkey",
    "credentialconfigured",
    "donkey",
    "hockey",
    "keyboard",
    "keycount",
    "keyid",
    "keyname",
    "monkey",
    "passkey",
    "sessioncount",
    "tokencount",
    "turkey",
}
_KNOWN_CONCATENATED_SENSITIVE_KEYS = {
    "accesstoken",
    "apikey",
    "authheader",
    "authenticationheader",
    "bottoken",
    "challengecredential",
    "clientsecret",
    "exchangecredential",
    "exchangesecret",
    "githubtoken",
    "idtoken",
    "managementkey",
    "proxyauthorization",
    "refreshtoken",
    "sessionsecret",
    "sessiontoken",
    "setcookie",
    "upstreamsecret",
    "webhookcredential",
    "webhookkey",
    "webhooksecret",
    "webhooktoken",
    "xapikey",
}
_URL_USERINFO_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*:(?:\\*/){2})"
    r"(?P<userinfo>[^/\s?#@\"']+)(?P<at>@|\\u0040)",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"
_CREDENTIAL_SUFFIX_WORDS = frozenset({"token", "key", "secret", "credential"})
_AUTHORIZATION_KEYS = r"(?:proxy[-_]?authorization|authorization)"
_QUOTED_AUTH_VALUE = r"(?P<quote>\\*[\"'])(?P<quoted>.*?)(?P=quote)"
_BARE_AUTH_VALUE = r"(?P<bare>(?!\[REDACTED\])[^\s\\\"',;&}\]]+)"
_AUTHORIZATION_RE = re.compile(
    rf"(?P<prefix>\b{_AUTHORIZATION_KEYS}\b(?:\\*[\"'])?\s*(?:=|:)\s*)"
    rf"(?:"
    rf"(?P<quote>\\*[\"'])(?P<quoted_scheme>(?:bearer|basic)\s+)?"
    rf"(?P<quoted>.*?)(?P=quote)|"
    rf"(?P<bare_scheme>(?:bearer|basic)\s+)?{_BARE_AUTH_VALUE}"
    rf")",
    re.IGNORECASE,
)
_AUTH_SCHEME_RE = re.compile(
    rf"(?P<prefix>\b(?P<scheme>bearer|basic)\s+)"
    rf"(?:{_QUOTED_AUTH_VALUE}|{_BARE_AUTH_VALUE})",
    re.IGNORECASE,
)
_AUTH_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]+\Z")
_AUTH_TRAILING_PUNCTUATION = ".,!?)"
# Quoted/unquoted plain, JSON, and backslash-escaped JSON key/value forms.
_KEY_VALUE_RE = re.compile(
    r"(?P<lead>(?:\\?[\"'])?)"
    r"(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,80})"
    r"(?P<trail>(?:\\?[\"'])?)"
    r"(?P<spacing>\s*(?::|=)\s*)"
    r"(?P<value>"
    r"(?P<escaped_quote>\\[\"'])(?P<escaped_value>.*?)(?P=escaped_quote)"
    r"|\"(?P<double_value>(?:\\.|[^\"\\])*)\""
    r"|'(?P<single_value>(?:\\.|[^'\\])*)'"
    r"|(?P<bare_value>(?!\[REDACTED\])[^\s,;}\]]+)"
    r")",
    re.IGNORECASE,
)


def revision(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def stable_candidate(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact candidate minus refresh/sync timestamps that naturally drift."""
    return {
        str(key): copy.deepcopy(item)
        for key, item in value.items()
        if str(key) not in _VOLATILE_CANDIDATE_FIELDS
    }


def candidate_revision(value: Mapping[str, Any]) -> str:
    return revision(stable_candidate(value))


def credential_fingerprint(value: Mapping[str, Any]) -> str:
    """Bind a plan to credentials without retaining/returning a derived hint."""
    selected = {
        str(key): copy.deepcopy(item)
        for key, item in value.items()
        if is_sensitive_key(key)
        or str(key) in {
            "provider", "type", "email", "subject", "sub", "workspace_id",
            "chatgpt_account_id", "project_id", "organization_id", "expired",
        }
    }
    return revision(selected)


def utc_datetime(value: Any) -> datetime | None:
    """Normalize persisted epoch/ISO values for RFC3339 UTC API output only."""
    if value is None or value == "" or value == -1 or value == "-1":
        return None
    parsed: datetime
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        epoch = float(value)
        if abs(epoch) >= 100_000_000_000:
            epoch /= 1000.0
        parsed = datetime.fromtimestamp(epoch, tz=timezone.utc)
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            epoch = float(raw)
        except ValueError:
            normalized = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
            try:
                parsed = datetime.fromisoformat(normalized)
            except ValueError:
                return None
        else:
            if abs(epoch) >= 100_000_000_000:
                epoch /= 1000.0
            parsed = datetime.fromtimestamp(epoch, tz=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_sensitive_key(key: object) -> bool:
    """Classify credential keys by real word/case boundaries, not substrings."""
    raw = str(key)
    normalized = "".join(char for char in raw.casefold() if char.isalnum())
    if normalized in _PUBLIC_KEY_NORMALIZED:
        return False
    words: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", raw):
        if not part:
            continue
        camel = re.findall(
            r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", part,
        )
        words.extend(word.casefold() for word in (camel or [part]))
    # A credential term inside a public identifier describes the identifier,
    # not credential material (for example publicKeyId or upstream_key_id).
    if words and words[-1] == "id":
        return False
    if normalized in _KNOWN_CONCATENATED_SENSITIVE_KEYS:
        return True
    word_set = set(words)
    if word_set.intersection(_SENSITIVE_KEY_WORDS):
        return True
    if (
        word_set.intersection({"auth", "authentication"})
        and word_set.intersection({"header", "headers"})
    ):
        return True
    # ALL_CAPS removes the lexical boundary before a suffix. Exact ordinary
    # words are allowlisted above; every other non-empty prefix is structural.
    if raw.isupper():
        folded = raw.casefold()
        return any(
            folded.endswith(word) and len(folded) > len(word)
            for word in _CREDENTIAL_SUFFIX_WORDS
        )
    return False


def _is_basic_base64_credential(candidate: str) -> bool:
    if len(candidate) < 8 or not _AUTH_TOKEN_RE.fullmatch(candidate):
        return False
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return False
    return b":" in decoded


def _looks_like_auth_credential(scheme: str, candidate: str) -> bool:
    if not candidate or not _AUTH_TOKEN_RE.fullmatch(candidate):
        return False
    lowered = candidate.casefold()
    marker_parts = {
        part for part in re.split(r"[^a-z0-9]+", lowered) if part
    }
    if lowered == "marker" or marker_parts.intersection(
        _CREDENTIAL_SUFFIX_WORDS | {"marker"}
    ):
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


def _redact_authorization(match: re.Match[str]) -> str:
    groups = match.groupdict()
    quote = groups.get("quote") or ""
    scheme = groups.get("quoted_scheme") or groups.get("bare_scheme") or ""
    bare = groups.get("bare") or ""
    # An already-redacted bare value can make the optional scheme backtrack and
    # appear to be the value. Preserve it so repeated boundary passes are safe.
    if bare.casefold() in {"bearer", "basic"} and re.match(
        r"\s+\[REDACTED\]", match.string[match.end():], re.IGNORECASE,
    ):
        return match.group(0)
    return match.group("prefix") + quote + scheme + _REDACTED + quote


def _redact_auth_scheme(match: re.Match[str]) -> str:
    groups = match.groupdict()
    quote = groups.get("quote") or ""
    candidate = groups.get("quoted") or groups.get("bare") or ""
    trailing = ""
    if not quote:
        stripped = candidate.rstrip(_AUTH_TRAILING_PUNCTUATION)
        trailing = candidate[len(stripped):]
        candidate = stripped
    if not _looks_like_auth_credential(match.group("scheme"), candidate):
        return match.group(0)
    return match.group("prefix") + quote + _REDACTED + quote + trailing


def _redact_key_value(match: re.Match[str]) -> str:
    normalized_key = "".join(
        char for char in match.group("key").casefold() if char.isalnum()
    )
    # Authorization assignments are consumed as a whole by _AUTHORIZATION_RE;
    # matching just the scheme here would leave or duplicate the credential.
    if normalized_key in {"authorization", "proxyauthorization"}:
        return match.group(0)
    if not is_sensitive_key(match.group("key")):
        return match.group(0)
    if match.group("escaped_quote"):
        quote = match.group("escaped_quote")
        public = quote + "[REDACTED]" + quote
    elif match.group("double_value") is not None:
        public = '"[REDACTED]"'
    elif match.group("single_value") is not None:
        public = "'[REDACTED]'"
    else:
        public = "[REDACTED]"
    return (
        match.group("lead") + match.group("key") + match.group("trail")
        + match.group("spacing") + public
    )


def sanitize_text(value: object) -> str:
    """Redact credential-shaped fragments while preserving useful error prose."""
    text = str(value)
    text = _URL_USERINFO_RE.sub(
        lambda match: f"{match.group('scheme')}[REDACTED]{match.group('at')}",
        text,
    )
    text = _AUTHORIZATION_RE.sub(_redact_authorization, text)
    # The optional backslash-quote groups cover both ordinary and escaped JSON.
    text = _KEY_VALUE_RE.sub(_redact_key_value, text)
    text = _AUTH_SCHEME_RE.sub(_redact_auth_scheme, text)
    return text


def _camel_key(key: object) -> str:
    raw = str(key)
    if raw == "account_key":
        return "accountId"
    head, *tail = raw.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def public_value(value: Any, *, camel_case_keys: bool = False) -> Any:
    """Recursively sanitize OAuth-owned Operation/response payloads."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            public_key = _camel_key(key) if camel_case_keys else str(key)
            result[public_key] = (
                "[REDACTED]"
                if is_sensitive_key(key)
                else public_value(item, camel_case_keys=camel_case_keys)
            )
        return result
    if isinstance(value, (list, tuple, set)):
        return [public_value(item, camel_case_keys=camel_case_keys) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, datetime):
        return utc_datetime(value)
    return sanitize_text(value)


def audit_failures(action: str, *, target_arg: str | None = None, target: str = "oauth"):
    """Record a stable failed domain audit without exposing exception text."""
    def decorate(method):
        signature = inspect.signature(method)

        @functools.wraps(method)
        def wrapped(self, *args, **kwargs):
            context = args[0] if args else kwargs.get("context")
            try:
                return method(self, *args, **kwargs)
            except BaseException:
                audit_target = target
                if target_arg is not None:
                    try:
                        bound = signature.bind(self, *args, **kwargs)
                        value = bound.arguments.get(target_arg, target)
                        audit_target = getattr(value, "value", value)
                    except Exception:
                        audit_target = target
                if context is not None:
                    self._audit(context, action, str(audit_target), "failed")
                raise

        return wrapped
    return decorate


def invalid_account(account: Mapping[str, Any]) -> bool:
    """Frozen TG invalid-list predicate: email plus auth_error."""
    return bool(account.get("email")) and account.get("disabled_reason") == "auth_error"

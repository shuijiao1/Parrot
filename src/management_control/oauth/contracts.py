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
    "keycount",
    "keyid",
    "keyname",
    "sessioncount",
    "tokencount",
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
_BEARER_RE = re.compile(
    r"(?i)(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+/=-]+)"
)
_BASIC_RE = re.compile(
    r"(?i)(?P<prefix>\bBasic\s+)(?P<value>[A-Za-z0-9._~+/=-]+)"
)
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
    r"|(?P<bare_value>[^\s,;}\]]+)"
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
    if normalized in _KNOWN_CONCATENATED_SENSITIVE_KEYS:
        return True
    words: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", raw):
        if not part:
            continue
        camel = re.findall(
            r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", part,
        )
        words.extend(word.casefold() for word in (camel or [part]))
    word_set = set(words)
    if word_set.intersection(_SENSITIVE_KEY_WORDS):
        return True
    return bool(
        word_set.intersection({"auth", "authentication"})
        and word_set.intersection({"header", "headers"})
    )


def _looks_like_auth_credential(candidate: str) -> bool:
    return len(candidate) >= 8 and (
        not candidate.isalpha() or not (candidate.islower() or candidate.isupper())
    )


def _redact_bearer(match: re.Match[str]) -> str:
    value = match.group("value")
    if not _looks_like_auth_credential(value):
        return match.group(0)
    return match.group("prefix") + "[REDACTED]"


def _redact_basic(match: re.Match[str]) -> str:
    token = match.group("value")
    padded = token + "=" * (-len(token) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        decoded = b""
    # RFC user-pass and opaque marker-shaped values are credentials. Plain
    # lower/upper-case prose such as "Basic routing mode" remains untouched.
    if b":" not in decoded and not _looks_like_auth_credential(token):
        return match.group(0)
    return match.group("prefix") + "[REDACTED]"


def _redact_key_value(match: re.Match[str]) -> str:
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
    text = _BEARER_RE.sub(_redact_bearer, text)
    text = _BASIC_RE.sub(_redact_basic, text)
    # The optional backslash-quote groups cover both ordinary and escaped JSON.
    text = _KEY_VALUE_RE.sub(_redact_key_value, text)
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

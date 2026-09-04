"""Explicit URL handling for the Channels API boundary."""

from __future__ import annotations

from src.management_control.public_safety import split_public_url, without_url_userinfo


def require_url_without_userinfo(value: str) -> str:
    """Pydantic validator that rejects URL userinfo without echoing the input."""
    try:
        parsed = split_public_url(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("URL could not be safely parsed") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL userinfo is not allowed")
    return value


def strip_url_userinfo(value: str) -> str:
    """Remove userinfo from a value explicitly known to be a channel URL."""
    try:
        return without_url_userinfo(value)
    except (TypeError, ValueError):
        return ""


def redact_credential_text(value: str | None) -> str | None:
    """Keep provider error prose unchanged; structured secrets are handled upstream."""
    return None if value is None else str(value)

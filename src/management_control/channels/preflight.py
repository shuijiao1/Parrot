"""Synchronous preflight for existing-channel asynchronous operations."""

from __future__ import annotations

from typing import Any

from src import provider_usage
from src.management_auth.principal import Capability

from ..errors import ManagementError, ManagementErrorCode


def validate_existing_operation(
    control: Any,
    context: Any,
    channel_id: str,
    *,
    model: str | None = None,
    require_provider_usage: bool = False,
) -> None:
    """Authorize and reject invalid targets before an Operation is accepted."""
    control._authorize(context, Capability.WRITE)
    channel = control._domain_channel(channel_id)
    if model is not None and model not in {
        item.get("real") for item in getattr(channel, "models", ())
    }:
        raise ManagementError(ManagementErrorCode.VALIDATION_FAILED)
    if require_provider_usage and provider_usage.spec_for(channel) is None:
        raise ManagementError(ManagementErrorCode.UNSUPPORTED_VALUE)

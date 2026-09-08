"""Shared URL and provider preset validation for channel actions."""

from __future__ import annotations

from typing import Any

from src.providers.catalog import ProviderPreset, get_preset

from ..errors import ErrorField, ManagementError, ManagementErrorCode


def validated_preset(
    provider_id: Any,
    provider_preset_id: Any,
    protocol: Any,
) -> ProviderPreset | None:
    if not provider_id and not provider_preset_id:
        return None
    if not provider_id or not provider_preset_id:
        raise ManagementError(ManagementErrorCode.VALIDATION_FAILED)
    preset = get_preset(str(provider_id), str(provider_preset_id))
    if preset is None or getattr(protocol, "value", protocol) not in preset.protocols:
        raise ManagementError(ManagementErrorCode.UNSUPPORTED_VALUE)
    return preset


def validate_base_url(value: str | None) -> None:
    """Apply the existing Telegram HTTP(S) scheme rule at the shared boundary."""
    if not value or not value.strip():
        raise ManagementError(
            ManagementErrorCode.VALIDATION_FAILED,
            fields=(ErrorField("baseUrl", "missing", "Base URL is required"),),
        )
    if not value.strip().startswith(("http://", "https://")):
        raise ManagementError(
            ManagementErrorCode.VALIDATION_FAILED,
            fields=(ErrorField("baseUrl", "invalid_scheme", "Base URL must start with http:// or https://"),),
        )

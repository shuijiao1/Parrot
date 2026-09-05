"""Shared provider preset validation for channel mutations."""

from __future__ import annotations

from typing import Any

from src.providers.catalog import ProviderPreset, get_preset

from ..errors import ManagementError, ManagementErrorCode


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

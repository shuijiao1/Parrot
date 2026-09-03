"""The single capability policy used by management adapters and controls."""

from __future__ import annotations

from dataclasses import dataclass

from .principal import Capability, ManagementPrincipal


@dataclass(frozen=True, slots=True)
class CapabilityDenied(PermissionError):
    capability: Capability

    def __str__(self) -> str:
        return f"management capability denied: {self.capability.value}"


def has_capability(principal: ManagementPrincipal, capability: Capability) -> bool:
    return capability in principal.capabilities


def authorize(principal: ManagementPrincipal, capability: Capability) -> None:
    """Enforce one capability without embedding role checks in callers."""
    if not has_capability(principal, capability):
        raise CapabilityDenied(capability)

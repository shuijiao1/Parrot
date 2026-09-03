"""Discovery schemas for the management API foundation."""

from __future__ import annotations

from src.management_auth.principal import Capability

from .base import StrictSchema


class EnumDescriptor(StrictSchema):
    name: str
    values: list[str]


class ManagementMetadataData(StrictSchema):
    apiVersion: str
    applicationVersion: str
    supportedCapabilities: list[Capability]
    enums: list[EnumDescriptor]
    documentationUrl: str


class CapabilityDomain(StrictSchema):
    domain: str
    capabilities: list[Capability]
    actions: list[str]
    providers: list[str]
    presets: list[str]
    protocols: list[str]
    modes: list[str]


class ManagementCapabilitiesData(StrictSchema):
    domains: list[CapabilityDomain]

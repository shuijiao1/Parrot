"""Typed discovery schemas for the Management API foundation."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from src.management_auth.principal import Capability

from .base import StrictSchema


class EnumDescriptor(StrictSchema):
    name: str = Field(description="Stable OpenAPI schema or operation field name")
    values: list[str] = Field(description="Values declared by the current public API schema")


class ManagementFeatureDescriptor(StrictSchema):
    id: str = Field(description="Management domain tag exposed by production routes")
    actionCount: int = Field(ge=1, description="Number of mounted operations in the domain")


class ManagementActionDescriptor(StrictSchema):
    operationId: str = Field(description="Unique OpenAPI operationId")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(description="OpenAPI path template under /api/management/v1")


class ManagementMetadataData(StrictSchema):
    apiVersion: str
    applicationVersion: str
    features: list[ManagementFeatureDescriptor]
    supportedCapabilities: list[Capability] = Field(
        description="Capability vocabulary supported by this product version"
    )
    principalCapabilities: list[Capability] = Field(
        description="Capabilities granted to the current authenticated principal"
    )
    enums: list[EnumDescriptor]
    documentationUrl: str


class CapabilityDomain(StrictSchema):
    domain: str = Field(description="Primary OpenAPI tag for this management domain")
    capabilities: list[Capability] = Field(
        deprecated=True,
        description=(
            "Deprecated v1 compatibility alias for the current principal's grants; "
            "use top-level principalCapabilities, not this field, for authorization"
        ),
    )
    actions: list[str] = Field(
        description=(
            "Actually mounted operationId strings. This preserves the v1 string element "
            "type but does not preserve the former placeholder action labels"
        )
    )
    actionDetails: list[ManagementActionDescriptor] = Field(
        description="Method and path details for the operationIds listed in actions"
    )
    providers: list[str] = Field(
        description="Provider identifiers constrained by this domain's schema or catalog"
    )
    presets: list[str] = Field(
        description="Qualified providerId/presetId identifiers from an existing catalog"
    )
    protocols: list[str] = Field(
        description="Protocol values constrained by this domain's public schema"
    )
    modes: list[str] = Field(
        description="Mode values constrained by this domain's public schema or catalog"
    )
    features: list[str] = Field(
        description="Named feature flags from an existing domain catalog"
    )


class ManagementCapabilitiesData(StrictSchema):
    supportedCapabilities: list[Capability] = Field(
        description="Capability vocabulary supported by this product version"
    )
    principalCapabilities: list[Capability] = Field(
        description="Capabilities granted to the current authenticated principal"
    )
    domains: list[CapabilityDomain]

"""Management discovery from mounted routes, declared schemas and the catalog."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping

from src.management_auth.principal import Capability

from .schemas.metadata import (
    CapabilityDomain,
    EnumDescriptor,
    ManagementActionDescriptor,
    ManagementFeatureDescriptor,
)


_MANAGEMENT_PREFIX = "/api/management/v1"
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")
# Domain semantics are explicit. Values remain owned by the referenced schemas;
# field names are never guessed to mean a provider, protocol or mode.
_DOMAIN_ENUMS = {
    "api-keys": {"modes": ("ApiKeySource",)},
    "management-channels": {
        "protocols": ("ChannelProtocol",),
        "modes": ("CompatibilityMode", "ManualChannelCreateRequest.mode", "PresetChannelCreateRequest.mode"),
    },
    "management-load-balancing": {"modes": ("LoadBalancingMode",)},
    "management-logs": {"protocols": ("RequestProtocol",)},
    "management-model-mapping": {"protocols": ("Ingress",)},
    "management-oauth": {
        "providers": ("OAuthProvider",),
        "modes": ("CchMode", "OAuthUsageDisplayMode"),
    },
    "management-retention": {"modes": ("RetentionSettingsData.mode",)},
    "management-system": {"modes": ("CchSettingsData.mode",)},
    "status-alerts": {"providers": ("StatusIncidentData.provider",)},
    "updates": {"modes": ("listUpdateBackups.mode",)},
}


@dataclass(frozen=True, slots=True)
class DiscoverySnapshot:
    features: tuple[ManagementFeatureDescriptor, ...]
    enums: tuple[EnumDescriptor, ...]
    domains: tuple[CapabilityDomain, ...]


def _management_operations(document):
    seen = set()
    for path, path_item in document.get("paths", {}).items():
        if not path.startswith(_MANAGEMENT_PREFIX):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            operation_id = operation.get("operationId")
            if not operation_id or operation_id in seen:
                raise ValueError(f"Missing or duplicate Management operationId: {operation_id}")
            if not operation.get("tags"):
                raise ValueError(f"Management operation {operation_id} has no domain tag")
            seen.add(operation_id)
            yield operation_id, method.upper(), path, operation


def _declared_enums(document, operations) -> dict[str, list[str]]:
    """Read declared enum/const values, resolving each referenced schema once."""
    schemas = document.get("components", {}).get("schemas", {})
    visited = set()
    enums: dict[str, list[str]] = {}

    def collect(schema, name):
        if not isinstance(schema, dict):
            return
        ref = schema.get("$ref", "")
        if ref.startswith("#/components/schemas/"):
            ref_name = ref.removeprefix("#/components/schemas/")
            if ref_name not in visited:
                visited.add(ref_name)
                collect(schemas.get(ref_name), ref_name)
            return
        values = schema.get("enum", [schema["const"]] if "const" in schema else [])
        values = [str(value) for value in values if value is not None]
        if values:
            target = enums.setdefault(name, [])
            target.extend(value for value in values if value not in target)
        for field, nested in schema.get("properties", {}).items():
            collect(nested, f"{name}.{field}")
        for key in ("items", "additionalProperties"):
            collect(schema.get(key), name)
        for key in ("allOf", "anyOf", "oneOf"):
            for nested in schema.get(key, []):
                collect(nested, name)

    for operation_id, _method, _path, operation in operations:
        for parameter in operation.get("parameters", []):
            collect(parameter.get("schema"), f"{operation_id}.{parameter['name']}")
        bodies = [(f"{operation_id}.request", operation.get("requestBody", {}))]
        bodies.extend(
            (f"{operation_id}.response.{status}", response)
            for status, response in operation.get("responses", {}).items()
        )
        for name, body in bodies:
            for media in body.get("content", {}).values():
                collect(media.get("schema"), name)
    for alias, source in (("authMethod", "AuthMethod"), ("operationStatus", "OperationStatus")):
        if source in enums:
            enums[alias] = list(enums[source])
    return enums


def build_discovery_snapshot(
    document: Mapping[str, object],
    *,
    channel_catalog: object | None = None,
    principal_capabilities: Iterable[Capability] = (),
) -> DiscoverySnapshot:
    operations = list(_management_operations(document))
    enums = _declared_enums(document, operations)
    by_domain = defaultdict(list)
    catalog_domain = None
    for operation_id, method, path, operation in operations:
        domain = operation["tags"][0]
        by_domain[domain].append(ManagementActionDescriptor(
            operationId=operation_id, method=method, path=path,
        ))
        if operation_id == "getChannelCatalog":
            catalog_domain = domain

    grants = sorted(set(principal_capabilities), key=lambda capability: capability.value)
    domains = []
    for domain, details in sorted(by_domain.items()):
        facets = {key: set() for key in ("providers", "presets", "protocols", "modes", "features")}
        for category, names in _DOMAIN_ENUMS.get(domain, {}).items():
            for name in names:
                facets[category].update(enums[name])
        if domain == catalog_domain and channel_catalog is not None:
            for provider in channel_catalog.providers:
                facets["providers"].add(provider.id)
                facets["presets"].update(f"{provider.id}/{preset.id}" for preset in provider.presets)
            facets["protocols"].update(item.value for item in channel_catalog.protocols)
            facets["modes"].update(item.value for item in channel_catalog.compatibility_modes)
            facets["features"].update(channel_catalog.features)
        details.sort(key=lambda item: item.operationId)
        domains.append(CapabilityDomain(
            domain=domain,
            capabilities=list(grants),
            actions=[item.operationId for item in details],
            actionDetails=details,
            **{key: sorted(values) for key, values in facets.items()},
        ))
    return DiscoverySnapshot(
        features=tuple(ManagementFeatureDescriptor(id=d.domain, actionCount=len(d.actions)) for d in domains),
        enums=tuple(EnumDescriptor(name=name, values=values) for name, values in sorted(enums.items())),
        domains=tuple(domains),
    )


def supported_capabilities() -> list[Capability]:
    return list(Capability)

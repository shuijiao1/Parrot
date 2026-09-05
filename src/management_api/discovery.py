"""Pure aggregation of Management API discovery data from public contracts.

The production OpenAPI document is the authority for domains, actions and enum
values.  The channel Control's read-only catalog is supplied by the caller for
provider preset data that intentionally is not encoded as an OpenAPI enum.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import re
from typing import Any, Iterable, Mapping, Sequence

from src.management_auth.principal import Capability

from .schemas.metadata import (
    CapabilityDomain,
    EnumDescriptor,
    ManagementActionDescriptor,
    ManagementFeatureDescriptor,
)


_MANAGEMENT_PREFIX = "/api/management/v1"
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")


@dataclass(frozen=True, slots=True)
class DiscoverySnapshot:
    features: tuple[ManagementFeatureDescriptor, ...]
    enums: tuple[EnumDescriptor, ...]
    domains: tuple[CapabilityDomain, ...]


@dataclass(slots=True)
class _DomainValues:
    actions: list[ManagementActionDescriptor] = field(default_factory=list)
    providers: set[str] = field(default_factory=set)
    presets: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    modes: set[str] = field(default_factory=set)
    features: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class _EnumHit:
    name: str
    values: tuple[str, ...]
    semantic_hint: str


def _append_unique(target: list[str], values: Iterable[str]) -> None:
    seen = set(target)
    for value in values:
        if value not in seen:
            target.append(value)
            seen.add(value)


def _enum_values(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    values: list[str] = []
    for item in raw:
        if item is None:
            continue
        if not isinstance(item, (str, int, float, bool)):
            return ()
        value = str(item)
        if value not in values:
            values.append(value)
    return tuple(values)


def _schema_ref_name(ref: object) -> str | None:
    prefix = "#/components/schemas/"
    if not isinstance(ref, str) or not ref.startswith(prefix):
        return None
    name = ref[len(prefix) :]
    return name if name and "/" not in name else None


def _walk_schema(
    schema: object,
    *,
    schemas: Mapping[str, object],
    context: str,
    semantic_hint: str,
    active_refs: frozenset[str] = frozenset(),
) -> Iterable[_EnumHit]:
    if not isinstance(schema, Mapping):
        return

    ref_name = _schema_ref_name(schema.get("$ref"))
    if ref_name is not None:
        if ref_name in active_refs:
            return
        target = schemas.get(ref_name)
        if target is not None:
            yield from _walk_schema(
                target,
                schemas=schemas,
                context=ref_name,
                semantic_hint=semantic_hint or ref_name,
                active_refs=active_refs | {ref_name},
            )
        return

    values = _enum_values(schema.get("enum"))
    if not values and "const" in schema:
        values = _enum_values([schema.get("const")])
    if values:
        yield _EnumHit(
            name=context,
            values=values,
            semantic_hint=semantic_hint or context,
        )

    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for property_name, property_schema in properties.items():
            if not isinstance(property_name, str):
                continue
            yield from _walk_schema(
                property_schema,
                schemas=schemas,
                context=f"{context}.{property_name}",
                semantic_hint=property_name,
                active_refs=active_refs,
            )

    for key in ("items", "additionalProperties"):
        nested = schema.get(key)
        if isinstance(nested, Mapping):
            yield from _walk_schema(
                nested,
                schemas=schemas,
                context=context,
                semantic_hint=semantic_hint,
                active_refs=active_refs,
            )

    for key in ("allOf", "anyOf", "oneOf"):
        alternatives = schema.get(key)
        if isinstance(alternatives, Sequence) and not isinstance(alternatives, (str, bytes)):
            for alternative in alternatives:
                yield from _walk_schema(
                    alternative,
                    schemas=schemas,
                    context=context,
                    semantic_hint=semantic_hint,
                    active_refs=active_refs,
                )


def _operation_schema_roots(
    operation_id: str,
    operation: Mapping[str, object],
) -> Iterable[tuple[object, str, str]]:
    parameters = operation.get("parameters")
    if isinstance(parameters, Sequence) and not isinstance(parameters, (str, bytes)):
        for index, parameter in enumerate(parameters):
            if not isinstance(parameter, Mapping):
                continue
            name = parameter.get("name")
            hint = name if isinstance(name, str) else f"parameter{index}"
            schema = parameter.get("schema")
            if schema is not None:
                yield schema, f"{operation_id}.{hint}", hint

    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        content = request_body.get("content")
        if isinstance(content, Mapping):
            for media in content.values():
                if isinstance(media, Mapping) and media.get("schema") is not None:
                    yield media["schema"], f"{operation_id}.request", "request"

    responses = operation.get("responses")
    if isinstance(responses, Mapping):
        for status_code, response in responses.items():
            if not isinstance(response, Mapping):
                continue
            content = response.get("content")
            if not isinstance(content, Mapping):
                continue
            for media in content.values():
                if isinstance(media, Mapping) and media.get("schema") is not None:
                    yield (
                        media["schema"],
                        f"{operation_id}.response.{status_code}",
                        "response",
                    )


def _enum_hits(
    operation_id: str,
    operation: Mapping[str, object],
    schemas: Mapping[str, object],
) -> Iterable[_EnumHit]:
    for schema, context, semantic_hint in _operation_schema_roots(operation_id, operation):
        yield from _walk_schema(
            schema,
            schemas=schemas,
            context=context,
            semantic_hint=semantic_hint,
        )


def _word_tokens(value: str) -> set[str]:
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|[0-9]+", value)
    return {word.lower() for word in words}


def _semantic_category(hit: _EnumHit) -> str | None:
    for tokens in (_word_tokens(hit.semantic_hint), _word_tokens(hit.name)):
        if "preset" in tokens:
            return "presets"
        if "protocol" in tokens or "ingress" in tokens:
            return "protocols"
        if "provider" in tokens:
            return "providers"
        if "mode" in tokens:
            return "modes"
    return None


def _components_schemas(document: Mapping[str, object]) -> Mapping[str, object]:
    components = document.get("components")
    if not isinstance(components, Mapping):
        return {}
    schemas = components.get("schemas")
    return schemas if isinstance(schemas, Mapping) else {}


def _management_operations(
    document: Mapping[str, object],
) -> Iterable[tuple[str, str, str, Mapping[str, object]]]:
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return
    seen: set[str] = set()
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith(_MANAGEMENT_PREFIX):
            continue
        if not isinstance(path_item, Mapping):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, Mapping):
                continue
            operation_id = operation.get("operationId")
            tags = operation.get("tags")
            if not isinstance(operation_id, str) or not operation_id:
                raise ValueError(f"Management operation {method.upper()} {path} has no operationId")
            if operation_id in seen:
                raise ValueError(f"Duplicate Management operationId: {operation_id}")
            if (
                not isinstance(tags, Sequence)
                or isinstance(tags, (str, bytes))
                or not tags
                or not isinstance(tags[0], str)
                or not tags[0]
            ):
                raise ValueError(f"Management operation {operation_id} has no domain tag")
            seen.add(operation_id)
            yield operation_id, method.upper(), path, operation


def _merge_channel_catalog(
    domains: dict[str, _DomainValues],
    operation_domains: Mapping[str, str],
    channel_catalog: object | None,
) -> None:
    domain_name = operation_domains.get("getChannelCatalog")
    if domain_name is None or channel_catalog is None:
        return
    domain = domains[domain_name]
    providers = getattr(channel_catalog, "providers", ())
    for provider in providers:
        provider_id = getattr(provider, "id", None)
        if not isinstance(provider_id, str) or not provider_id:
            continue
        domain.providers.add(provider_id)
        for preset in getattr(provider, "presets", ()):
            preset_id = getattr(preset, "id", None)
            if isinstance(preset_id, str) and preset_id:
                domain.presets.add(f"{provider_id}/{preset_id}")
    for protocol in getattr(channel_catalog, "protocols", ()):
        value = getattr(protocol, "value", protocol)
        if isinstance(value, str) and value:
            domain.protocols.add(value)
    for mode in getattr(channel_catalog, "compatibility_modes", ()):
        value = getattr(mode, "value", mode)
        if isinstance(value, str) and value:
            domain.modes.add(value)
    for feature in getattr(channel_catalog, "features", ()):
        if isinstance(feature, str) and feature:
            domain.features.add(feature)


def build_discovery_snapshot(
    document: Mapping[str, object],
    *,
    channel_catalog: object | None = None,
) -> DiscoverySnapshot:
    """Build one deterministic snapshot without calling network or mutation APIs."""

    schemas = _components_schemas(document)
    domains: dict[str, _DomainValues] = defaultdict(_DomainValues)
    operation_domains: dict[str, str] = {}
    enum_values: dict[str, list[str]] = {}

    for operation_id, method, path, operation in _management_operations(document):
        tags = operation["tags"]
        domain_name = tags[0]
        operation_domains[operation_id] = domain_name
        domain = domains[domain_name]
        domain.actions.append(
            ManagementActionDescriptor(
                operationId=operation_id,
                method=method,
                path=path,
            )
        )
        for hit in _enum_hits(operation_id, operation, schemas):
            _append_unique(enum_values.setdefault(hit.name, []), hit.values)
            category = _semantic_category(hit)
            if category is not None:
                getattr(domain, category).update(hit.values)

    _merge_channel_catalog(domains, operation_domains, channel_catalog)

    domain_models = tuple(
        CapabilityDomain(
            domain=domain_name,
            actions=sorted(values.actions, key=lambda item: item.operationId),
            providers=sorted(values.providers),
            presets=sorted(values.presets),
            protocols=sorted(values.protocols),
            modes=sorted(values.modes),
            features=sorted(values.features),
        )
        for domain_name, values in sorted(domains.items())
    )
    features = tuple(
        ManagementFeatureDescriptor(id=domain.domain, actionCount=len(domain.actions))
        for domain in domain_models
    )
    enums = tuple(
        EnumDescriptor(name=name, values=values)
        for name, values in sorted(enum_values.items())
    )
    return DiscoverySnapshot(features=features, enums=enums, domains=domain_models)


def supported_capabilities() -> list[Capability]:
    """Return product capability vocabulary, never a principal's grants."""

    return list(Capability)

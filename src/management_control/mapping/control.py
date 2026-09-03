"""Shared model mapping and metadata use cases.

This module owns validation and orchestration. Telegram keeps rendering/state while
FastAPI converts these DTOs into public schemas.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping

from src import compact_rescue, config, model_mapping, model_metadata, model_pricing
from src.channel import registry
from src.management_auth.principal import Capability
from src.management_control.context import AuditSink, ManagementContext
from src.management_control.errors import ManagementError, ManagementErrorCode
from src.management_control.models.common import DomainControl, ListPage, stable_revision
from src.management_control.operations import OperationStore
from src.oauth_ids import provider_from_channel_key


@dataclass(frozen=True, slots=True)
class MappingRecord:
    alias: str
    real_model: str
    source_line: str
    revision: str


@dataclass(frozen=True, slots=True)
class IngressDefaultRecord:
    ingress: str
    model_id: str | None
    revision: str


@dataclass(frozen=True, slots=True)
class InventoryRecord:
    model_id: str
    family: str
    provider: str
    channel_id: str
    account_id: str | None
    outbound_model: str
    revision: str


@dataclass(frozen=True, slots=True)
class MetadataRecord:
    model_id: str
    target: str | None
    provider_id: str | None
    catalog_model_id: str | None
    scope: str
    scope_id: str | None
    outbound_model: str | None
    source: str
    authority: str
    effective: Mapping[str, Any]
    raw: Mapping[str, Any]
    revision: str


@dataclass(frozen=True, slots=True)
class CatalogRecord:
    key: str
    model_id: str
    name: str
    provider_id: str
    provider_name: str
    metadata: Mapping[str, Any]
    revision: str


class MappingControl(DomainControl):
    INGRESS_LINES = model_mapping.INGRESS_LINES
    GLOBAL_MAPPING_LINE = model_mapping.GLOBAL_MAPPING_LINE
    INGRESS_LABEL = model_mapping.INGRESS_LABEL
    MetadataBinding = model_metadata.MetadataBinding
    ModelInventoryItem = model_metadata.ModelInventoryItem

    _sync_lock = threading.Lock()
    _sync_running = False

    def __init__(
        self,
        *,
        audit_sink: AuditSink | None = None,
        operation_store: OperationStore | None = None,
    ) -> None:
        super().__init__(audit_sink=audit_sink)
        self._operation_store = operation_store

    @staticmethod
    def _mapping_snapshot() -> dict[str, Any]:
        cfg = config.get()
        return {
            "modelMapping": cfg.get("modelMapping") or {},
            "ingressDefaultModel": cfg.get("ingressDefaultModel") or {},
        }

    @classmethod
    def _mapping_revision(cls) -> str:
        return stable_revision(cls._mapping_snapshot())

    @staticmethod
    def _mapping_sources() -> dict[str, str]:
        root = config.get().get("modelMapping") or {}
        if not isinstance(root, dict):
            return {}
        if root and not any(isinstance(value, dict) for value in root.values()):
            return {str(alias): "global" for alias in root}
        sources: dict[str, str] = {}
        for line in model_mapping.INGRESS_LINES:
            values = root.get(line) or {}
            if isinstance(values, dict):
                sources.update({str(alias): line for alias in values})
        values = root.get(model_mapping.GLOBAL_MAPPING_LINE) or {}
        if isinstance(values, dict):
            sources.update({str(alias): "global" for alias in values})
        return sources

    def list_mappings(
        self,
        context: ManagementContext,
        *,
        query: str | None,
        sort: str,
        page: int,
        page_size: int,
    ) -> ListPage[MappingRecord]:
        self._read(context)
        revision = self._mapping_revision()
        sources = self._mapping_sources()
        items = [
            MappingRecord(alias, real, sources.get(alias, "legacy"), revision)
            for alias, real in model_mapping.get_ingress_map("global").items()
        ]
        needle = (query or "").strip().casefold()
        if needle:
            items = [
                item for item in items
                if needle in item.alias.casefold() or needle in item.real_model.casefold()
            ]
        key = {
            "alias": lambda item: item.alias.casefold(),
            "realModel": lambda item: item.real_model.casefold(),
            "sourceLine": lambda item: (item.source_line, item.alias.casefold()),
        }[sort]
        return self._paginate(
            sorted(items, key=key), page, page_size, revision=revision
        )

    def put_mapping(
        self,
        context: ManagementContext,
        alias: str,
        real_model: str,
        *,
        expected_revision: str | None = None,
    ) -> MappingRecord:
        actual = self._write(context)
        alias = str(alias or "").strip()
        real = str(real_model or "").strip()
        if not alias:
            raise self._validation("alias", "EMPTY", "alias must not be empty")
        if not real:
            raise self._validation("realModel", "EMPTY", "realModel must not be empty")
        if alias == real:
            raise self._validation("realModel", "SELF_MAPPING", "alias and realModel must differ")
        with config.serialized_updates():
            self._check_revision(expected_revision, self._mapping_revision())
            model_mapping.set_mapping("global", alias, real)
        revision = self._mapping_revision()
        self._audit(actual, "model_mapping.put", alias, "succeeded")
        return MappingRecord(alias, real, "global", revision)

    def delete_mapping(
        self,
        context: ManagementContext,
        alias: str,
        *,
        expected_revision: str | None = None,
    ) -> None:
        actual = self._write(context, Capability.DESTRUCTIVE)
        with config.serialized_updates():
            self._check_revision(expected_revision, self._mapping_revision())
            if not model_mapping.remove_mapping("global", alias):
                raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        self._audit(actual, "model_mapping.delete", alias, "succeeded")

    def get_ingress_default(
        self, context: ManagementContext, ingress: str,
    ) -> IngressDefaultRecord:
        self._read(context)
        self._validate_ingress(ingress)
        return IngressDefaultRecord(
            ingress, model_mapping.get_default_model(ingress), self._mapping_revision()
        )

    def put_ingress_default(
        self,
        context: ManagementContext,
        ingress: str,
        model_id: str,
        *,
        expected_revision: str | None = None,
    ) -> IngressDefaultRecord:
        actual = self._write(context)
        self._validate_ingress(ingress)
        model_id = str(model_id or "").strip()
        if model_id not in set(model_mapping.list_available_models_for(ingress)):
            raise self._validation("modelId", "UNKNOWN_MODEL", "model is not available for ingress")
        with config.serialized_updates():
            self._check_revision(expected_revision, self._mapping_revision())
            model_mapping.set_default(ingress, model_id)
        record = IngressDefaultRecord(ingress, model_id, self._mapping_revision())
        self._audit(actual, "ingress_default.put", ingress, "succeeded")
        return record

    def delete_ingress_default(
        self,
        context: ManagementContext,
        ingress: str,
        *,
        expected_revision: str | None = None,
    ) -> None:
        actual = self._write(context, Capability.DESTRUCTIVE)
        self._validate_ingress(ingress)
        with config.serialized_updates():
            self._check_revision(expected_revision, self._mapping_revision())
            if not model_mapping.clear_default(ingress):
                raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        self._audit(actual, "ingress_default.delete", ingress, "succeeded")

    @staticmethod
    def _validate_ingress(ingress: str) -> None:
        if ingress not in model_mapping.INGRESS_LINES:
            raise MappingControl._validation(
                "ingress", "UNSUPPORTED_INGRESS", "unsupported ingress"
            )

    @staticmethod
    def _metadata_snapshot(inventory: list[Any] | None = None) -> dict[str, Any]:
        cfg = config.get()
        items = list(model_metadata.inventory_items()) if inventory is None else inventory
        return {
            "modelBindings": cfg.get("modelBindings") or {},
            "compressionModel": cfg.get("compressionModel") or "",
            "catalog": model_pricing.catalog_status(),
            "inventory": [
                (
                    item.scope_key,
                    item.scope_type,
                    item.client_visible_model,
                    item.outbound_model,
                )
                for item in items
            ],
        }

    @classmethod
    def _metadata_revision(cls, inventory: list[Any] | None = None) -> str:
        return stable_revision(cls._metadata_snapshot(inventory))

    def list_inventory(
        self,
        context: ManagementContext,
        *,
        provider: str | None,
        family: str | None,
        query: str | None,
        sort: str,
        page: int,
        page_size: int,
    ) -> ListPage[InventoryRecord]:
        self._read(context)
        inventory = list(model_metadata.inventory_items())
        revision = self._metadata_revision(inventory)
        channel_by_key = {channel.key: channel for channel in registry.all_channels()}
        values: list[InventoryRecord] = []
        for item in inventory:
            channel = channel_by_key.get(item.scope_key)
            protocol = str(getattr(channel, "protocol", "anthropic") or "anthropic")
            channel_family = "anthropic" if protocol == "anthropic" else "openai"
            channel_provider = str(getattr(channel, "provider", "") or "")
            if not channel_provider:
                channel_provider = provider_from_channel_key(item.scope_key) or channel_family
            values.append(InventoryRecord(
                model_id=item.client_visible_model,
                family=channel_family,
                provider=channel_provider,
                channel_id=item.scope_key,
                account_id=item.scope_key if item.scope_type == "oauth" else None,
                outbound_model=item.outbound_model,
                revision=revision,
            ))
        needle = (query or "").strip().casefold()
        if provider:
            values = [item for item in values if item.provider == provider]
        if family:
            values = [item for item in values if item.family == family]
        if needle:
            values = [
                item for item in values
                if needle in item.model_id.casefold()
                or needle in item.channel_id.casefold()
                or needle in item.provider.casefold()
            ]
        key = {
            "modelId": lambda item: (item.model_id.casefold(), item.channel_id),
            "provider": lambda item: (item.provider, item.model_id.casefold()),
            "channelId": lambda item: (item.channel_id, item.model_id.casefold()),
        }[sort]
        return self._paginate(
            sorted(values, key=key), page, page_size, revision=revision
        )

    @staticmethod
    def _metadata_record(
        model_id: str,
        binding: model_metadata.MetadataBinding | None,
        revision: str,
        *,
        scope: str = "global",
        scope_id: str | None = None,
    ) -> MetadataRecord:
        if binding is None:
            return MetadataRecord(
                model_id=model_id,
                target=None,
                provider_id=None,
                catalog_model_id=None,
                scope=scope,
                scope_id=scope_id,
                outbound_model=None,
                source="none",
                authority="none",
                effective={},
                raw={},
                revision=revision,
            )
        raw = model_pricing.catalog_model(binding.target) or {}
        return MetadataRecord(
            model_id=model_id,
            target=binding.target,
            provider_id=binding.provider_id,
            catalog_model_id=binding.catalog_model_id,
            scope="global" if binding.scope_key is None else (
                "oauth" if binding.scope_key.startswith("oauth:") else "api"
            ),
            scope_id=binding.scope_key,
            outbound_model=binding.outbound_model,
            source=binding.source,
            authority=binding.authority,
            effective=dict(binding.metadata),
            raw=dict(raw),
            revision=revision,
        )

    def list_metadata(
        self,
        context: ManagementContext,
        *,
        scope: str | None,
        scope_id: str | None,
        query: str | None,
        sort: str,
        page: int,
        page_size: int,
    ) -> ListPage[MetadataRecord]:
        self._read(context)
        inventory = list(model_metadata.inventory_items())
        revision = self._metadata_revision(inventory)
        bindings = list(model_metadata.list_bindings())
        records: list[MetadataRecord] = []
        if scope_id:
            models = {
                item.client_visible_model for item in inventory
                if item.scope_key == scope_id
            }
            models.update(
                item.client_visible_model for item in bindings
                if item.scope_key == scope_id
            )
            requested_scope = "oauth" if scope_id.startswith("oauth:") else "api"
            for model_id in sorted(models, key=str.casefold):
                binding = model_metadata.resolve_binding(model_id, scope_key=scope_id)
                records.append(self._metadata_record(
                    model_id, binding, revision,
                    scope=requested_scope, scope_id=scope_id,
                ))
        else:
            records.extend(
                self._metadata_record(binding.client_visible_model, binding, revision)
                for binding in bindings
            )
            represented_globals = {
                item.model_id for item in records if item.scope == "global"
            }
            for model_id in sorted(
                {item.client_visible_model for item in inventory} - represented_globals,
                key=str.casefold,
            ):
                binding = model_metadata.resolve_binding(model_id)
                records.append(self._metadata_record(model_id, binding, revision))
        if scope:
            records = [item for item in records if item.scope == scope]
        needle = (query or "").strip().casefold()
        if needle:
            records = [
                item for item in records
                if needle in item.model_id.casefold()
                or needle in (item.target or "").casefold()
            ]
        key = {
            "modelId": lambda item: item.model_id.casefold(),
            "provider": lambda item: ((item.provider_id or ""), item.model_id.casefold()),
            "source": lambda item: (item.source, item.model_id.casefold()),
        }[sort]
        return self._paginate(
            sorted(records, key=key), page, page_size, revision=revision
        )

    def get_metadata(
        self,
        context: ManagementContext,
        model_id: str,
        *,
        scope_id: str | None = None,
    ) -> MetadataRecord:
        self._read(context)
        inventory = list(model_metadata.inventory_items())
        known = {item.client_visible_model for item in inventory}
        known.update(item.client_visible_model for item in model_metadata.list_bindings())
        if model_id not in known:
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        binding = model_metadata.resolve_binding(model_id, scope_key=scope_id)
        return self._metadata_record(
            model_id, binding, self._metadata_revision(inventory)
        )

    @staticmethod
    def _scope_key(
        scope: str,
        *,
        account_id: str | None,
        channel_id: str | None,
    ) -> str | None:
        if scope == "global":
            return None
        value = account_id if scope == "oauth" else channel_id
        field = "accountId" if scope == "oauth" else "channelId"
        if not value:
            raise MappingControl._validation(field, "REQUIRED", f"{field} is required")
        channel = registry.get_channel(value)
        expected_type = "oauth" if scope == "oauth" else "api"
        if channel is None or channel.type != expected_type:
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        return value

    def put_binding(
        self,
        context: ManagementContext,
        model_id: str,
        *,
        scope: str,
        target_model_id: str,
        provider_id: str,
        account_id: str | None,
        channel_id: str | None,
        outbound_model: str | None,
        expected_revision: str | None = None,
    ) -> MetadataRecord:
        actual = self._write(context)
        scope_key = self._scope_key(scope, account_id=account_id, channel_id=channel_id)
        target = str(target_model_id or "").strip().lower()
        if not target.startswith(provider_id.lower() + "/"):
            raise self._validation(
                "providerId", "TARGET_PROVIDER_MISMATCH", "providerId must match targetModelId"
            )
        if scope_key and not outbound_model:
            raise self._validation(
                "outboundModel", "REQUIRED", "scoped binding requires outboundModel"
            )
        try:
            with config.serialized_updates():
                self._check_revision(expected_revision, self._metadata_revision())
                model_metadata.set_binding(
                    model_id,
                    target,
                    scope_key=scope_key,
                    outbound_model=outbound_model,
                    source="management-api" if context.actor.session_id else "manual",
                )
        except ValueError as exc:
            raise self._validation("targetModelId", "UNKNOWN_CATALOG_MODEL", str(exc)) from exc
        binding = model_metadata.resolve_binding(
            model_id, scope_key=scope_key, outbound_model=outbound_model
        )
        self._audit(actual, "model_metadata.binding.put", model_id, "succeeded")
        return self._metadata_record(model_id, binding, self._metadata_revision())

    def delete_binding_control(
        self,
        context: ManagementContext,
        model_id: str,
        *,
        scope: str,
        account_id: str | None,
        channel_id: str | None,
        expected_revision: str | None = None,
    ) -> None:
        actual = self._write(context, Capability.DESTRUCTIVE)
        scope_key = self._scope_key(scope, account_id=account_id, channel_id=channel_id)
        with config.serialized_updates():
            self._check_revision(expected_revision, self._metadata_revision())
            if not model_metadata.delete_binding(model_id, scope_key=scope_key):
                raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        self._audit(actual, "model_metadata.binding.delete", model_id, "succeeded")

    def search_catalog(
        self,
        context: ManagementContext,
        *,
        provider: str | None,
        query: str | None,
        sort: str,
        page: int,
        page_size: int,
    ) -> ListPage[CatalogRecord]:
        self._read(context)
        needle = " ".join((query or "").strip().casefold().split())
        tokens = needle.split()
        values = []
        catalog_revision = stable_revision(model_pricing.catalog_status())
        for item in model_pricing.catalog_models():
            if provider and item["provider_id"] != provider:
                continue
            combined = " ".join(str(value).casefold() for value in item.values())
            if tokens and not all(token in combined for token in tokens):
                continue
            values.append(CatalogRecord(
                key=item["key"],
                model_id=item["id"],
                name=item["name"],
                provider_id=item["provider_id"],
                provider_name=item["provider_name"],
                metadata=model_pricing.catalog_metadata(item["key"]) or {},
                revision=catalog_revision,
            ))
        key = {
            "name": lambda item: (item.name.casefold(), item.provider_name.casefold()),
            "provider": lambda item: (item.provider_name.casefold(), item.name.casefold()),
            "modelId": lambda item: (item.model_id.casefold(), item.provider_name.casefold()),
        }[sort]
        return self._paginate(
            sorted(values, key=key), page, page_size, revision=catalog_revision
        )

    def get_compression(self, context: ManagementContext) -> tuple[str | None, str]:
        self._read(context)
        return model_metadata.get_compression_model(), self._metadata_revision()

    def put_compression(
        self,
        context: ManagementContext,
        model_id: str,
        *,
        expected_revision: str | None = None,
    ) -> tuple[str, str]:
        actual = self._write(context)
        known = {item.client_visible_model for item in model_metadata.inventory_items()}
        if model_id not in known:
            raise self._validation("modelId", "UNKNOWN_MODEL", "model is not in inventory")
        with config.serialized_updates():
            self._check_revision(expected_revision, self._metadata_revision())
            model_metadata.set_compression_model(model_id)
        self._audit(actual, "compression_model.put", model_id, "succeeded")
        return model_id, self._metadata_revision()

    def delete_compression(
        self,
        context: ManagementContext,
        *,
        expected_revision: str | None = None,
    ) -> None:
        actual = self._write(context, Capability.DESTRUCTIVE)
        with config.serialized_updates():
            self._check_revision(expected_revision, self._metadata_revision())
            if not model_metadata.clear_compression_model():
                raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        self._audit(actual, "compression_model.delete", "compression-model", "succeeded")

    def perform_metadata_sync(self, context: ManagementContext | None = None) -> dict[str, Any]:
        actual = self._write(context)
        with self._sync_lock:
            if self.__class__._sync_running:
                raise ManagementError(
                    ManagementErrorCode.OPERATION_ALREADY_RUNNING,
                    retryable=True,
                )
            self.__class__._sync_running = True
        try:
            catalog_updated = False
            try:
                catalog_updated = model_pricing.refresh_remote_catalog_sync()
            except Exception as exc:
                print(f"[metadata] models.dev refresh failed; using local catalog: {exc}")
            model_pricing.reload_local_catalog()
            result = dict(model_metadata.auto_sync_metadata())
            result["catalog"] = "updated" if catalog_updated else "local"
            self._audit(actual, "model_metadata.sync", "catalog", "succeeded")
            return result
        finally:
            with self._sync_lock:
                self.__class__._sync_running = False

    def start_metadata_sync(
        self,
        context: ManagementContext,
        *,
        scope: str = "full",
        provider_id: str | None = None,
        account_id: str | None = None,
        channel_id: str | None = None,
    ):
        self._write(context)
        if self._operation_store is None:
            raise ManagementError(ManagementErrorCode.SERVICE_NOT_READY)
        fingerprint = stable_revision({
            "scope": scope,
            "providerId": provider_id,
            "accountId": account_id,
            "channelId": channel_id,
        })
        replay = self._idempotent_replay(
            context,
            action="model_metadata.sync",
            fingerprint=fingerprint,
            operation_store=self._operation_store,
        )
        if replay is not None:
            return replay
        with self._sync_lock:
            if self.__class__._sync_running:
                raise ManagementError(
                    ManagementErrorCode.OPERATION_ALREADY_RUNNING,
                    retryable=True,
                )
            self.__class__._sync_running = True
        inventory = list(model_metadata.inventory_items())
        if scope == "provider":
            selected = []
            channels = {channel.key: channel for channel in registry.all_channels()}
            for item in inventory:
                channel = channels.get(item.scope_key)
                provider = str(getattr(channel, "provider", "") or "")
                provider = provider or provider_from_channel_key(item.scope_key) or ""
                if provider == provider_id:
                    selected.append(item)
            inventory = selected
        elif scope == "account":
            inventory = [item for item in inventory if item.scope_key == account_id and item.scope_type == "oauth"]
        elif scope == "channel":
            inventory = [item for item in inventory if item.scope_key == channel_id and item.scope_type == "api"]
        if scope != "full" and not inventory:
            with self._sync_lock:
                self.__class__._sync_running = False
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        try:
            operation = self._operation_store.create(
                context, kind="model_metadata.sync", cancellable=False
            )
            self._remember_idempotency(
                context,
                action="model_metadata.sync",
                fingerprint=fingerprint,
                operation_id=operation.id,
            )
        except Exception:
            with self._sync_lock:
                self.__class__._sync_running = False
            raise

        def worker() -> None:
            try:
                self._operation_store.mark_running(operation.id)
                catalog_updated = False
                try:
                    catalog_updated = model_pricing.refresh_remote_catalog_sync()
                except Exception:
                    catalog_updated = False
                model_pricing.reload_local_catalog()
                result = dict(model_metadata.auto_sync_metadata(inventory))
                result["catalog"] = "updated" if catalog_updated else "local"
                result["scope"] = scope
                self._operation_store.succeed(operation.id, result)
                self._audit(context, "model_metadata.sync", "catalog", "succeeded")
            except Exception:
                self._operation_store.fail(
                    operation.id,
                    code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
                    message="metadata sync failed",
                    retryable=True,
                )
            finally:
                with self._sync_lock:
                    self.__class__._sync_running = False

        threading.Thread(target=worker, daemon=True, name="management-metadata-sync").start()
        return operation

    # Telegram compatibility façade. Every call remains a control use case while
    # preserving existing renderer input objects and exact exception behavior.
    def get_ingress_map(self, ingress: str):
        self._read(None)
        return model_mapping.get_ingress_map(ingress)

    def get_default_model(self, ingress: str):
        self._read(None)
        return model_mapping.get_default_model(ingress)

    def list_available_models_for(self, ingress: str):
        self._read(None)
        return model_mapping.list_available_models_for(ingress)

    def set_mapping(self, ingress: str, alias: str, real: str) -> None:
        actual = self._write(None)
        model_mapping.set_mapping(ingress, alias, real)
        self._audit(actual, "model_mapping.put", alias, "succeeded")

    def remove_mapping(self, ingress: str, alias: str) -> bool:
        actual = self._write(None, Capability.DESTRUCTIVE)
        result = model_mapping.remove_mapping(ingress, alias)
        self._audit(actual, "model_mapping.delete", alias, "succeeded" if result else "unchanged")
        return result

    def set_default(self, ingress: str, real: str) -> None:
        actual = self._write(None)
        model_mapping.set_default(ingress, real)
        self._audit(actual, "ingress_default.put", ingress, "succeeded")

    def clear_default(self, ingress: str) -> bool:
        actual = self._write(None, Capability.DESTRUCTIVE)
        result = model_mapping.clear_default(ingress)
        self._audit(actual, "ingress_default.delete", ingress, "succeeded" if result else "unchanged")
        return result

    def list_bindings(self):
        self._read(None)
        return model_metadata.list_bindings()

    def resolve_binding(self, *args, **kwargs):
        self._read(None)
        return model_metadata.resolve_binding(*args, **kwargs)

    def inventory_items(self):
        self._read(None)
        return model_metadata.inventory_items()

    def auto_sync_metadata(self):
        return self.perform_metadata_sync()

    def set_binding(self, *args, **kwargs):
        actual = self._write(None)
        result = model_metadata.set_binding(*args, **kwargs)
        self._audit(actual, "model_metadata.binding.put", str(args[0]), "succeeded")
        return result

    def delete_binding(self, *args, **kwargs):
        actual = self._write(None, Capability.DESTRUCTIVE)
        result = model_metadata.delete_binding(*args, **kwargs)
        self._audit(actual, "model_metadata.binding.delete", str(args[0]), "succeeded" if result else "unchanged")
        return result

    def get_compression_model(self):
        self._read(None)
        return model_metadata.get_compression_model()

    def set_compression_model(self, model: str):
        actual = self._write(None)
        result = model_metadata.set_compression_model(model)
        self._audit(actual, "compression_model.put", model, "succeeded")
        return result

    def clear_compression_model(self):
        actual = self._write(None, Capability.DESTRUCTIVE)
        result = model_metadata.clear_compression_model()
        self._audit(actual, "compression_model.delete", "compression-model", "succeeded" if result else "unchanged")
        return result

    def compact_trigger_tokens(self, model: str) -> int:
        self._read(None)
        return model_metadata.compact_trigger_tokens(model)

    def chunk_target_tokens(self) -> int:
        self._read(None)
        return compact_rescue.chunk_target_tokens()

    def catalog_status(self):
        self._read(None)
        return model_pricing.catalog_status()

    def catalog_models(self):
        self._read(None)
        return model_pricing.catalog_models()

    def catalog_metadata(self, key: str):
        self._read(None)
        return model_pricing.catalog_metadata(key)

    def catalog_model(self, key: str):
        self._read(None)
        return model_pricing.catalog_model(key)

    def canonical_official_model(self, model: str):
        self._read(None)
        return model_pricing.canonical_official_model(model)

    def catalog_providers(self):
        self._read(None)
        return model_pricing.catalog_providers()

    def catalog_provider_models(self, provider: str):
        self._read(None)
        return model_pricing.catalog_provider_models(provider)

    def refresh_remote_catalog_sync(self):
        self._write(None)
        return model_pricing.refresh_remote_catalog_sync()

    def reload_local_catalog(self):
        self._read(None)
        return model_pricing.reload_local_catalog()


mapping_control = MappingControl()

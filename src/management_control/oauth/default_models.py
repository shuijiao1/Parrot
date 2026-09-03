"""Default-model OAuth control use cases."""

from __future__ import annotations

import asyncio
from typing import Iterable

from src.management_auth.principal import Capability
from src.management_control.context import ManagementContext
from src.management_control.errors import ManagementError, ManagementErrorCode
from src.management_control.operations import ManagementOperation, OperationStore

from .models import (
    OAuthDefaultModelReference,
    OAuthDefaultModels,
    OAuthDefaultModelsResult,
    OAuthFamily,
)


class OAuthDefaultModelsControlMixin:
    def default_models_snapshot(self, family: OAuthFamily | str) -> list[str]:
        value = family.value if isinstance(family, OAuthFamily) else str(family)
        return self.backend.default_models(value)

    def static_default_models_snapshot(self, family: OAuthFamily | str) -> list[str]:
        value = family.value if isinstance(family, OAuthFamily) else str(family)
        return self.backend.static_default_models(value)

    def scan_default_model_references(
        self,
        context: ManagementContext,
        family: OAuthFamily | str,
        removed: set[str],
    ) -> dict:
        self._require(context, Capability.READ)
        value = family.value if isinstance(family, OAuthFamily) else str(family)
        return self.backend.scan_default_model_references(value, removed)

    def replace_default_models_raw(
        self,
        context: ManagementContext,
        family: OAuthFamily | str,
        models: Iterable[str],
        removed: set[str],
        *,
        cleanup_references: bool,
    ) -> dict:
        self._require(context, Capability.WRITE)
        value = family.value if isinstance(family, OAuthFamily) else str(family)
        result = self.backend.replace_default_models(
            value,
            list(models),
            removed,
            cleanup=cleanup_references,
        )
        self._audit(context, "oauth.default-models.replace", value)
        return result

    def get_default_models(self, context: ManagementContext, family: OAuthFamily) -> OAuthDefaultModels:
        self._require(context, Capability.READ)
        models = self.backend.default_models(family.value)
        references = self.backend.scan_default_model_references(family.value, set(models))
        flat: list[OAuthDefaultModelReference] = []
        for item in references["apiKeys"]:
            flat.extend(OAuthDefaultModelReference("apiKey", item["name"], model) for model in item["hits"])
        flat.extend(
            OAuthDefaultModelReference("mapping", f"{item['ingress']}:{item['alias']}", item["real"])
            for item in references["mappings"]
        )
        flat.extend(
            OAuthDefaultModelReference("ingressDefault", item["ingress"], item["value"])
            for item in references["defaults"]
        )
        return OAuthDefaultModels(
            family, tuple(models), tuple(flat), self._value_revision(models),
        )

    def replace_default_models(
        self,
        context: ManagementContext,
        family: OAuthFamily,
        models: Iterable[str],
        *,
        cleanup_references: bool,
        expected_revision: str | None = None,
    ) -> OAuthDefaultModelsResult:
        self._require(context, Capability.WRITE)
        values = list(models)
        if len(values) > 200 or len(values) != len(set(values)) or any(
            not value or any(char in value for char in ("\\", " ", "\x00")) for value in values
        ):
            raise ManagementError(ManagementErrorCode.VALIDATION_FAILED)
        current = self.backend.default_models(family.value)
        if expected_revision and expected_revision != self._value_revision(current):
            raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
        removed = set(current) - set(values)
        summary = self.replace_default_models_raw(
            context,
            family,
            values,
            removed,
            cleanup_references=cleanup_references,
        )
        return OAuthDefaultModelsResult(
            family=family,
            models=tuple(values),
            cleaned_api_keys=tuple(item["name"] for item in summary["keys_cleaned"]),
            skipped_api_keys=tuple(summary["keys_skipped_empty"]),
            removed_mappings=tuple(f"{item['ingress']}:{item['alias']}" for item in summary["mappings_removed"]),
            cleared_defaults=tuple(summary["defaults_cleared"]),
            revision=self._value_revision(values),
        )

    def discover_default_models(
        self, context: ManagementContext, family: OAuthFamily, store: OperationStore,
    ) -> ManagementOperation:
        self._require(context, Capability.WRITE)

        def worker() -> dict:
            models = self.backend.static_default_models(family.value)
            source = "static"
            if family is OAuthFamily.XAI:
                account_id = self.backend.first_enabled_account_id("xai")
                if account_id is None:
                    raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE)
                token = asyncio.run(self.backend.ensure_valid_token(account_id))
                models = asyncio.run(self.backend.discover_models(self.backend.xai_models_url(), token))
                models = [
                    model for model in models
                    if not model.lower().startswith("grok-imagine")
                    and "imagine-image" not in model.lower()
                    and "imagine-video" not in model.lower()
                ]
                source = "upstream"
            return {"family": family.value, "models": models, "source": source}

        return self._start_operation(
            context, store, kind="oauth.default-models.discover", worker=worker,
        )

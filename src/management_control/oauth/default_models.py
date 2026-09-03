"""Default-model OAuth control use cases."""

from __future__ import annotations

import asyncio
from typing import Iterable

from src.management_auth.principal import Capability
from src.management_control.context import ManagementContext
from src.management_control.errors import ErrorField, ManagementError, ManagementErrorCode
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
        state = self.backend.default_models_state(family.value)
        models = state["models"]
        references = state["references"]
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
            family, tuple(models), tuple(flat), self._value_revision(state),
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
        try:
            values = list(models)
            fields = [
                ErrorField(f"models[{index}]", "INVALID_MODEL", "Invalid model ID")
                for index, value in enumerate(values)
                if not value or any(char in value for char in ("\\", " ", "\x00"))
            ]
            seen: set[str] = set()
            for index, value in enumerate(values):
                if value in seen:
                    fields.append(ErrorField(
                        f"models[{index}]", "DUPLICATE_MODEL", "Duplicate model ID",
                    ))
                seen.add(value)
            if len(values) > 200:
                fields.append(ErrorField(
                    "models[200]", "TOO_MANY_MODELS",
                    "At most 200 models are allowed",
                ))
            if fields:
                raise ManagementError(
                    ManagementErrorCode.VALIDATION_FAILED, fields=fields,
                )
            current_state = self.backend.default_models_state(family.value)
            current = current_state["models"]
            current_revision = self._value_revision(current_state)
            if expected_revision and expected_revision != current_revision:
                raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
            removed = set(current) - set(values)
            if (removed or cleanup_references) and not expected_revision:
                raise ManagementError(ManagementErrorCode.CONFIRMATION_REQUIRED)
            outcome = self.backend.replace_default_models_conditional(
                family.value,
                values,
                removed,
                cleanup=cleanup_references,
                expected_state=current_state,
            )
            if outcome.get("status") != "updated":
                raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
            summary = outcome["summary"]
            new_state = self.backend.default_models_state(family.value)
            result = OAuthDefaultModelsResult(
                family=family,
                models=tuple(values),
                cleaned_api_keys=tuple(item["name"] for item in summary["keys_cleaned"]),
                skipped_api_keys=tuple(summary["keys_skipped_empty"]),
                removed_mappings=tuple(f"{item['ingress']}:{item['alias']}" for item in summary["mappings_removed"]),
                cleared_defaults=tuple(summary["defaults_cleared"]),
                revision=self._value_revision(new_state),
            )
        except BaseException:
            self._audit(context, "oauth.default-models.replace", family.value, "failed")
            raise
        self._audit(context, "oauth.default-models.replace", family.value)
        return result

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

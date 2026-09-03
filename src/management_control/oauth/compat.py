"""Compatibility-oriented OAuth control use cases used by existing adapters.

These operations keep the v0.31.13 Telegram orchestration intact while ensuring
that every business mutation crosses the same transport-neutral control boundary
as the Management API.  They deliberately return the existing domain shapes;
typed public API use cases remain on :class:`OAuthControl` itself.
"""

from __future__ import annotations

from typing import Iterable

from src.management_auth.principal import Capability
from src.management_control.context import ManagementContext


class OAuthCompatibilityControlMixin:
    """Narrow raw-shape operations needed while preserving frozen TG rendering."""

    def save_usage_snapshot(
        self,
        context: ManagementContext,
        account_id: str,
        usage: dict,
        *,
        email: str | None = None,
    ) -> dict:
        self._require(context, Capability.WRITE)
        preserved = self.backend.preserve_antigravity_summary(account_id, usage)
        self.backend.quota_save(
            account_id,
            self.backend.flatten_usage(preserved),
            email=email if email is not None else self.backend.account_email(account_id),
        )
        self._audit(context, "oauth.usage.snapshot.save", account_id)
        return preserved

    def evaluate_usage(self, context: ManagementContext, account_id: str, usage: dict) -> dict | None:
        self._require(context, Capability.WRITE)
        result = self.backend.evaluate_quota(account_id, usage)
        if result is not None:
            self._audit(context, "oauth.quota.evaluate", account_id)
        return result

    def set_account_disabled_models_raw(
        self,
        context: ManagementContext,
        account_id: str,
        models: Iterable[str],
        *,
        visible_models: Iterable[str] | None = None,
    ) -> set[str]:
        self._require(context, Capability.WRITE)
        self._account(account_id)
        result = self.backend.set_account_disabled_models(
            account_id, models, visible_models=visible_models,
        )
        self._audit(context, "oauth.models.update", account_id)
        return result

    def set_account_model_disabled_raw(
        self,
        context: ManagementContext,
        account_id: str,
        model_id: str,
        disabled: bool,
    ) -> bool:
        self._require(context, Capability.WRITE)
        self._account(account_id)
        result = self.backend.set_account_model_disabled(account_id, model_id, disabled)
        self._audit(context, "oauth.models.update", account_id)
        return result

    def set_cursor_disabled_models_raw(
        self,
        context: ManagementContext,
        account_id: str,
        models: Iterable[str],
        *,
        visible_models: Iterable[str] | None = None,
    ) -> set[str]:
        self._require(context, Capability.WRITE)
        self._account(account_id)
        result = self.backend.set_cursor_disabled_models(
            account_id, models, visible_models=visible_models,
        )
        self._audit(context, "oauth.models.update", account_id)
        return result

    def set_cursor_max_context_default_raw(
        self,
        context: ManagementContext,
        account_id: str,
        model_id: str,
        enabled: bool,
    ) -> bool:
        self._require(context, Capability.WRITE)
        self._account(account_id)
        result = self.backend.set_cursor_max_context_default(account_id, model_id, enabled)
        self._audit(context, "oauth.models.settings.update", account_id)
        return result

    def clear_model_error(
        self,
        context: ManagementContext,
        account_id: str,
        model_id: str,
    ) -> None:
        self._require(context, Capability.WRITE)
        self._account(account_id)
        self.backend.clear_errors(account_id, model_id)
        self._audit(context, "oauth.errors.clear", account_id)

    def upsert_openai_account_entry(
        self,
        context: ManagementContext,
        entry: dict,
    ) -> bool:
        """Compatibility helper: add or replace one exact OpenAI identity."""
        self._require(context, Capability.SECRETS_WRITE)
        existing = self.backend.find_exact_identity(entry)
        if existing is None:
            result = self.backend.add_account_if_absent(entry)
            if result.get("status") != "added":
                raise RuntimeError("OAuth identity appeared concurrently")
            account_id = str(result.get("account_key") or self.backend.account_id(entry))
            self._audit(context, "oauth.account.create", account_id)
            return False
        account_id, _snapshot = existing
        result = self.backend.replace_exact_identity(account_id, entry)
        if result.get("status") != "replaced":
            raise RuntimeError("OAuth identity changed concurrently")
        self._audit(context, "oauth.account.replace", account_id)
        return True

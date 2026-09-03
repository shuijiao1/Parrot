"""Authoritative adapters from OAuth controls to the existing domain modules."""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Iterable

from src import affinity, config, cooldown, load_balancing, log_db, oauth_manager, state_db
from src.cursor_bridge import catalog as cursor_model_catalog
from src.models_discovery import discover_models
from src.oauth import antigravity as antigravity_provider
from src.oauth import cursor as cursor_provider
from src.oauth import openai as openai_provider
from src.oauth import xai as xai_provider
from src.oauth.openai_import import parse_openai_import_payload


_FAMILY_CONFIG_PATHS = {
    "anthropic": ("oauthDefaultModels",),
    "antigravity": ("antigravityOAuth", "defaultModels"),
    "openai": ("openaiOAuth", "defaultModels"),
    "xai": ("xaiOAuth", "defaultModels"),
}
_FAMILY_INGRESSES = {
    "anthropic": {"anthropic"},
    "antigravity": {"openai-chat", "openai-responses"},
    "openai": {"openai-chat", "openai-responses"},
    "xai": {"openai-chat", "openai-responses"},
}


class OAuthBackend:
    """Small, patch-friendly wrapper over the repository's existing OAuth APIs."""

    def config_snapshot(self) -> dict:
        return copy.deepcopy(config.get())

    def default_config_snapshot(self) -> dict:
        return copy.deepcopy(config.DEFAULT_CONFIG)

    def list_accounts(self) -> list[dict]:
        return oauth_manager.list_accounts()

    def get_account(self, account_id: str) -> dict | None:
        return oauth_manager.get_account(account_id)

    def account_id(self, account: dict) -> str:
        return oauth_manager.get_account_key(account)

    def provider_of(self, account_or_id: dict | str) -> str:
        return oauth_manager.provider_of(account_or_id)

    def resolve_account_id(self, value: str | None) -> str | None:
        return oauth_manager.resolve_account_key(value)

    def resolve_account_id_or_none(self, value: str | None) -> str | None:
        try:
            return oauth_manager.resolve_account_key(value)
        except oauth_manager.AmbiguousOAuthAccountKey:
            return None

    def account_email(self, account_id: str) -> str:
        return oauth_manager.account_key_to_email(account_id)

    def find_exact_identity(self, entry: dict) -> tuple[str, dict] | None:
        return oauth_manager.find_exact_identity(entry)

    def add_account_if_absent(self, entry: dict) -> dict:
        return oauth_manager.add_account_if_identity_absent(entry)

    def replace_exact_identity(self, account_id: str, entry: dict) -> dict:
        return oauth_manager.replace_exact_identity(account_id, entry)

    def delete_account(self, account_id: str) -> None:
        oauth_manager.delete_account(account_id)

    def set_enabled(
        self,
        account_id: str,
        enabled: bool,
        *,
        reason: str | None = None,
    ) -> None:
        oauth_manager.set_enabled(account_id, enabled, reason=reason)

    def update_max_concurrent(self, account_id: str, value: int) -> None:
        oauth_manager.update_max_concurrent(account_id, value)

    async def force_refresh(self, account_id: str) -> str:
        return await oauth_manager.force_refresh(account_id)

    async def fetch_usage(self, account_id: str) -> dict:
        return await oauth_manager.fetch_usage(account_id)

    async def fetch_usage_snapshot(self, account_id: str, *, force: bool = True) -> dict:
        return await oauth_manager.fetch_usage_snapshot(account_id, force=force)

    def flatten_usage(self, usage: dict) -> dict:
        return oauth_manager.flatten_usage(usage)

    def usage_from_quota_row(self, row: dict) -> dict:
        return oauth_manager.usage_from_quota_row(row)

    def preserve_antigravity_summary(self, account_id: str, usage: dict) -> dict:
        return oauth_manager.preserve_antigravity_cached_summary(account_id, usage)

    def preserve_openai_reset_details(self, account_id: str, usage: dict) -> dict:
        return oauth_manager.preserve_openai_reset_credit_details(account_id, usage)

    def evaluate_quota(self, account_id: str, usage: dict) -> dict | None:
        return oauth_manager.evaluate_and_toggle_by_usage(account_id, usage)

    def evaluate_cached_quota(self, account_id: str) -> dict | None:
        return oauth_manager.evaluate_and_toggle_by_cached_quota(account_id)

    def quota_load(self, account_id: str) -> dict | None:
        return state_db.quota_load(account_id)

    def quota_save(self, account_id: str, usage: dict, *, email: str | None = None) -> None:
        state_db.quota_save(account_id, usage, email=email)

    def now_ms(self) -> int:
        return state_db.now_ms()

    def cooldown_entries(self) -> list[dict]:
        return cooldown.active_entries()

    def cooldown_state(self, channel_key: str, model_id: str) -> dict | None:
        return cooldown.get_state(channel_key, model_id)

    def clear_errors(self, account_id: str, model_id: str | None = None) -> None:
        cooldown.clear(f"oauth:{account_id}", model_id)

    def clear_all_errors(self) -> int:
        channel_keys = sorted({
            entry["channel_key"]
            for entry in cooldown.active_entries()
            if str(entry.get("channel_key") or "").startswith("oauth:")
        })
        for channel_key in channel_keys:
            cooldown.clear(channel_key, model=None)
        return len(channel_keys)

    def clear_affinity(self, account_id: str) -> None:
        channel_key = f"oauth:{account_id}"
        affinity.delete_by_channel(channel_key)
        affinity.client_delete_by_channel(channel_key)

    def account_model_selection(self, account_or_id: dict | str) -> dict:
        return oauth_manager.account_model_selection(account_or_id)

    def account_disabled_models(self, account_or_id: dict | str) -> set[str]:
        return oauth_manager.account_disabled_models(account_or_id)

    def set_account_model_disabled(self, account_id: str, model_id: str, disabled: bool) -> bool:
        return oauth_manager.set_account_model_disabled(account_id, model_id, disabled)

    def set_account_disabled_models(
        self,
        account_id: str,
        models: Iterable[str],
        *,
        visible_models: Iterable[str] | None = None,
    ) -> set[str]:
        return oauth_manager.set_account_disabled_models(
            account_id, models, visible_models=visible_models,
        )

    def cursor_disabled_models(self, account_or_id: dict | str) -> set[str]:
        return oauth_manager.cursor_disabled_models(account_or_id)

    def set_cursor_disabled_models(
        self,
        account_id: str,
        models: Iterable[str],
        *,
        visible_models: Iterable[str] | None = None,
    ) -> set[str]:
        return oauth_manager.set_cursor_disabled_models(
            account_id, models, visible_models=visible_models,
        )

    def cursor_max_context_default(self, account_or_id: dict | str, model_id: str) -> bool:
        return oauth_manager.cursor_max_context_default(account_or_id, model_id)

    def set_cursor_max_context_default(self, account_id: str, model_id: str, enabled: bool) -> bool:
        return oauth_manager.set_cursor_max_context_default(account_id, model_id, enabled)

    async def refresh_account_models(self, account_id: str) -> dict:
        return await oauth_manager.refresh_account_models(account_id)

    def start_account_model_refresh(self, account_id: str):
        return oauth_manager.start_account_model_refresh(account_id)

    def reset_quota(self, account_id: str) -> dict:
        return oauth_manager.reset_quota(account_id)

    async def redeem_openai_reset_credit(self, account_id: str, idempotency_key: str) -> dict:
        return await oauth_manager.redeem_openai_rate_limit_reset_credit(
            account_id, idempotency_key=idempotency_key,
        )

    def reorder_accounts(self, account_ids: list[str]) -> None:
        wanted = list(account_ids)

        def mutate(cfg: dict) -> None:
            accounts = cfg.get("oauthAccounts", [])
            by_id = {oauth_manager.get_account_key(account): account for account in accounts}
            cfg["oauthAccounts"] = [by_id[item] for item in wanted]

        config.update(mutate)

    def reorder_accounts_preserving_unlisted(self, account_ids: list[str]) -> None:
        order = {account_id: index for index, account_id in enumerate(account_ids)}

        def mutate(cfg: dict) -> None:
            accounts = list(cfg.get("oauthAccounts") or [])
            ordered = [
                account for account in accounts
                if oauth_manager.get_account_key(account) in order
            ]
            ordered.sort(
                key=lambda account: order.get(
                    oauth_manager.get_account_key(account), 10**9,
                )
            )
            rest = [
                account for account in accounts
                if oauth_manager.get_account_key(account) not in order
            ]
            cfg["oauthAccounts"] = ordered + rest

        config.update(mutate)

    def update_account_display_name(self, account_id: str, display_name: str | None) -> None:
        def mutate(cfg: dict) -> None:
            for account in cfg.get("oauthAccounts", []):
                if oauth_manager.get_account_key(account) != account_id:
                    continue
                if display_name:
                    account["label"] = display_name
                else:
                    account.pop("label", None)
                return
            raise ValueError("OAuth account not found")

        config.update(mutate)

    def get_settings(self) -> tuple[bool, int, float, str]:
        cfg = config.get()
        quota = cfg.get("quotaMonitor") or {}
        return (
            bool(quota.get("enabled", False)),
            int(quota.get("intervalSeconds", 60) or 60),
            float(quota.get("disableThresholdPercent", 95) or 95),
            str(cfg.get("cchMode") or "disabled"),
        )

    def update_settings(
        self,
        *,
        quota_enabled: bool | None = None,
        interval_seconds: int | None = None,
        threshold_percent: float | None = None,
        cch_mode: str | None = None,
    ) -> None:
        def mutate(cfg: dict) -> None:
            quota = cfg.setdefault("quotaMonitor", {})
            if quota_enabled is not None:
                quota["enabled"] = bool(quota_enabled)
            if interval_seconds is not None:
                quota["intervalSeconds"] = int(interval_seconds)
            if threshold_percent is not None:
                quota["disableThresholdPercent"] = float(threshold_percent)
                quota["resumeThresholdPercent"] = float(threshold_percent)
            if cch_mode is not None:
                cfg["cchMode"] = cch_mode

        config.update(mutate)

    def get_preferences(self) -> tuple[str, bool]:
        cfg = config.get()
        return (
            str(cfg.get("oauthUsageDisplayMode") or "used"),
            bool(cfg.get("quotaProgressBar", True)),
        )

    def update_preferences(
        self,
        *,
        usage_display_mode: str | None = None,
        quota_progress_bar: bool | None = None,
    ) -> None:
        def mutate(cfg: dict) -> None:
            if usage_display_mode is not None:
                cfg["oauthUsageDisplayMode"] = usage_display_mode
            if quota_progress_bar is not None:
                cfg["quotaProgressBar"] = bool(quota_progress_bar)

        config.update(mutate)

    @staticmethod
    def _models_from(cfg: dict, family: str) -> list[str]:
        path = _FAMILY_CONFIG_PATHS[family]
        value: object = cfg
        for part in path:
            value = value.get(part) if isinstance(value, dict) else None
        return [str(item) for item in (value or []) if isinstance(item, str) and item.strip()]

    def default_models(self, family: str) -> list[str]:
        return self._models_from(config.get(), family)

    def static_default_models(self, family: str) -> list[str]:
        return self._models_from(config.DEFAULT_CONFIG, family)

    def scan_default_model_references(self, family: str, removed: set[str]) -> dict:
        cfg = config.get()
        ingresses = _FAMILY_INGRESSES[family]
        api_keys: list[dict] = []
        would_empty: list[str] = []
        for name, entry in (cfg.get("apiKeys") or {}).items():
            if not isinstance(entry, dict):
                continue
            allowed = entry.get("allowedModels") or []
            if not isinstance(allowed, list) or not allowed:
                continue
            hits = sorted(model for model in allowed if model in removed)
            if hits:
                api_keys.append({"name": name, "hits": hits})
                if not [model for model in allowed if model not in removed]:
                    would_empty.append(name)
        mappings: list[dict] = []
        for ingress in ingresses:
            for alias, real in sorted(((cfg.get("modelMapping") or {}).get(ingress) or {}).items()):
                if isinstance(real, str) and real in removed:
                    mappings.append({"ingress": ingress, "alias": alias, "real": real})
        defaults = [
            {"ingress": ingress, "value": (cfg.get("ingressDefaultModel") or {}).get(ingress)}
            for ingress in ingresses
            if isinstance((cfg.get("ingressDefaultModel") or {}).get(ingress), str)
            and (cfg.get("ingressDefaultModel") or {}).get(ingress) in removed
        ]
        return {
            "apiKeys": api_keys,
            "mappings": mappings,
            "defaults": defaults,
            "would_empty_keys": would_empty,
        }

    def replace_default_models(
        self,
        family: str,
        models: list[str],
        removed: set[str],
        *,
        cleanup: bool,
    ) -> dict:
        summary = {
            "keys_cleaned": [],
            "keys_skipped_empty": [],
            "mappings_removed": [],
            "defaults_cleared": [],
        }
        path = _FAMILY_CONFIG_PATHS[family]
        ingresses = _FAMILY_INGRESSES[family]

        def mutate(cfg: dict) -> None:
            if len(path) == 1:
                cfg[path[0]] = list(models)
            else:
                cfg.setdefault(path[0], {})[path[1]] = list(models)
            if not cleanup or not removed:
                return
            for name, entry in (cfg.get("apiKeys") or {}).items():
                if not isinstance(entry, dict):
                    continue
                allowed = entry.get("allowedModels") or []
                if not isinstance(allowed, list) or not allowed:
                    continue
                kept = [model for model in allowed if model not in removed]
                removed_here = [model for model in allowed if model in removed]
                if not removed_here:
                    continue
                if not kept:
                    summary["keys_skipped_empty"].append(name)
                else:
                    entry["allowedModels"] = kept
                    summary["keys_cleaned"].append({"name": name, "removed": removed_here})
            mappings = cfg.get("modelMapping") or {}
            for ingress in ingresses:
                line = mappings.get(ingress)
                if not isinstance(line, dict):
                    continue
                for alias in list(line):
                    if line.get(alias) in removed:
                        del line[alias]
                        summary["mappings_removed"].append({"ingress": ingress, "alias": alias})
            defaults = cfg.get("ingressDefaultModel") or {}
            for ingress in ingresses:
                if defaults.get(ingress) in removed:
                    del defaults[ingress]
                    summary["defaults_cleared"].append(ingress)

        config.update(mutate)
        return summary

    def xai_models_url(self) -> str:
        cfg = config.get().get("xaiOAuth") or {}
        base = str(cfg.get("apiBaseUrl") or cfg.get("baseUrl") or "https://api.x.ai/v1").rstrip("/")
        return base if base.endswith("/models") else base + "/models"

    def first_enabled_account_id(self, provider: str) -> str | None:
        for account in oauth_manager.list_accounts():
            if (
                oauth_manager.provider_of(account) == provider
                and account.get("enabled", True)
                and not account.get("disabled_reason")
            ):
                return oauth_manager.get_account_key(account)
        return None

    async def ensure_valid_token(self, account_id: str) -> str:
        return await oauth_manager.ensure_valid_token(account_id)

    async def discover_models(self, url: str, token: str) -> list[str]:
        return await discover_models(url, token)

    def parse_import(self, kind: str, payload, *, filename: str = "") -> list[dict]:
        return parse_openai_import_payload(kind, payload, filename=filename)

    def cursor_catalog_records(self, account: dict) -> list[dict]:
        return cursor_model_catalog.catalog_records(account)

    def cursor_catalog_record(self, account: dict, model_id: str) -> dict | None:
        return cursor_model_catalog.find_record(account, model_id)

    def channel_model_stats(self, *args, **kwargs):
        return log_db.channel_model_stats(*args, **kwargs)

    def tokens_for_channel(self, *args, **kwargs):
        return log_db.tokens_for_channel(*args, **kwargs)

    def tokens_for_channel_models(self, *args, **kwargs):
        return log_db.tokens_for_channel_models(*args, **kwargs)

    def load_balancing_initialized(self) -> bool:
        return load_balancing.is_initialized()

    def sync_channel_added(self, channel_key: str, family: str) -> None:
        load_balancing.sync_channel_added(channel_key, family)

    async def enrich_openai_reset_credit_details(self, *args, **kwargs):
        return await oauth_manager.enrich_openai_reset_credit_details(*args, **kwargs)

    async def fetch_openai_reset_credits(self, *args, **kwargs):
        return await oauth_manager.fetch_openai_rate_limit_reset_credits(*args, **kwargs)

    def ensure_openai_metadata_fresh_sync(self, *args, **kwargs):
        return oauth_manager.ensure_openai_metadata_fresh_sync(*args, **kwargs)

    async def ensure_openai_metadata_fresh(self, *args, **kwargs):
        return await oauth_manager.ensure_openai_metadata_fresh(*args, **kwargs)

    async def refresh_cursor_models(self, *args, **kwargs):
        return await oauth_manager.refresh_cursor_models(*args, **kwargs)

    def fable_display_from_quota_row(self, *args, **kwargs):
        return oauth_manager.fable_display_from_quota_row(*args, **kwargs)

    def claude_plan_label(self, *args, **kwargs):
        return oauth_manager.claude_plan_label(*args, **kwargs)

    def claude_fable_models(self, *args, **kwargs):
        return oauth_manager.claude_fable_models(*args, **kwargs)

    def extract_utils_percent(self, *args, **kwargs):
        return oauth_manager.extract_utils_percent(*args, **kwargs)

    def model_sync_foreground_timeout_seconds(self) -> float:
        return float(oauth_manager.OAUTH_MODEL_SYNC_FOREGROUND_TIMEOUT_SECONDS)

    @staticmethod
    def is_cursor_auth_pending(exc: BaseException) -> bool:
        return isinstance(exc, cursor_provider.CursorAuthPending)

    # Provider calls remain separate so flows can preserve provider-specific
    # protocol behavior while keeping adapters out of provider modules. Resolve
    # attributes at call time so the repository's fake-provider tests keep working.
    def claude_pkce_generate(self): return oauth_manager.pkce_generate()
    def claude_build_login_url(self, *args, **kwargs): return oauth_manager.build_login_url(*args, **kwargs)
    def claude_exchange_code(self, *args, **kwargs): return oauth_manager.exchange_code(*args, **kwargs)
    async def claude_fetch_profile(self, *args, **kwargs): return await oauth_manager.fetch_profile(*args, **kwargs)
    def claude_extract_plan(self, *args, **kwargs): return oauth_manager.extract_claude_plan_info(*args, **kwargs)
    def openai_pkce_generate(self): return openai_provider.pkce_generate()
    def openai_build_login_url(self, *args, **kwargs): return openai_provider.build_login_url(*args, **kwargs)
    def openai_exchange_code(self, *args, **kwargs): return openai_provider.exchange_code_sync(*args, **kwargs)
    def openai_refresh(self, *args, **kwargs): return openai_provider.refresh_sync(*args, **kwargs)
    def openai_decode_id_token(self, *args, **kwargs): return openai_provider.decode_id_token(*args, **kwargs)
    def openai_extract_user_info(self, *args, **kwargs): return openai_provider.extract_user_info(*args, **kwargs)
    def xai_pkce_generate(self): return xai_provider.pkce_generate()
    def xai_discover(self): return xai_provider.discover_sync()
    def xai_build_login_url(self, *args, **kwargs): return xai_provider.build_login_url(*args, **kwargs)
    def xai_exchange_code(self, *args, **kwargs): return xai_provider.exchange_code_sync(*args, **kwargs)
    def xai_refresh(self, *args, **kwargs): return xai_provider.refresh_sync(*args, **kwargs)
    def xai_decode_id_token(self, *args, **kwargs): return xai_provider.decode_id_token(*args, **kwargs)
    def xai_extract_user_info(self, *args, **kwargs): return xai_provider.extract_user_info(*args, **kwargs)
    def xai_authorization_url(self): return xai_provider.authorization_url()
    def xai_token_url(self): return xai_provider.token_url()
    def xai_redirect_uri(self): return xai_provider.redirect_uri()
    def xai_api_base_url(self): return xai_provider.api_base_url()
    def cursor_generate_login(self): return cursor_provider.generate_login()
    def cursor_poll_login(self, *args, **kwargs): return cursor_provider.poll_login_once(*args, **kwargs)
    def cursor_subject(self, *args, **kwargs): return cursor_provider.subject_from_access_token(*args, **kwargs)
    def cursor_profile(self, *args, **kwargs): return cursor_provider.fetch_profile_sync(*args, **kwargs)
    def cursor_usage(self, *args, **kwargs): return cursor_provider.fetch_usage_sync(*args, **kwargs)
    def cursor_label(self, *args, **kwargs): return cursor_provider.account_label(*args, **kwargs)
    def antigravity_build_login_url(self, *args, **kwargs): return antigravity_provider.build_login_url(*args, **kwargs)
    def antigravity_complete_login(self, *args, **kwargs): return antigravity_provider.complete_login_sync(*args, **kwargs)
    def antigravity_parse_callback(self, *args, **kwargs): return antigravity_provider.parse_callback_url(*args, **kwargs)
    def antigravity_token_url(self): return antigravity_provider.token_url()
    def antigravity_redirect_uri(self): return antigravity_provider.redirect_uri()
    def antigravity_api_base_url(self): return antigravity_provider.api_base_url()

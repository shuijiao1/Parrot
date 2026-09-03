"""GPT image and xAI Imagine media settings control."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from src import config, image_db
from src.openai import images_simple
from src.management_auth.principal import Capability

from ..context import AuditSink, ManagementContext
from ..errors import ManagementError, ManagementErrorCode
from .common import (
    ConfigGateway,
    ModuleConfigGateway,
    audit,
    ensure_revision,
    invalid_field,
    require,
    revision_for,
    rfc3339_utc,
    string_list,
)


@dataclass(frozen=True, slots=True)
class ImageSettings:
    enabled: bool
    cache_enabled: bool
    main_model: str
    tool_model: str
    cache_path: str
    cache_retention_days: int
    cache_max_bytes: int
    revision: str


@dataclass(frozen=True, slots=True)
class ImageAccountState:
    account_id: str
    email: str
    oauth_enabled: bool
    image_enabled: bool
    image_cooldown_until: str | None
    missing_account_id: bool
    revision: str


@dataclass(frozen=True, slots=True)
class XaiMediaSettings:
    image_models: tuple[str, ...]
    video_models: tuple[str, ...]
    job_ttl_seconds: int
    request_timeout_seconds: int
    revision: str


@dataclass(frozen=True, slots=True)
class CachedImageLog:
    id: int
    action: str
    account_email: str
    paths: tuple[str, ...]


class MediaGateway(Protocol):
    @property
    def image_defaults(self) -> dict[str, Any]: ...
    @property
    def xai_defaults(self) -> dict[str, Any]: ...
    @property
    def data_dir(self) -> str: ...
    def image_settings(self) -> dict[str, Any]: ...
    def image_accounts(self) -> list[dict[str, Any]]: ...
    def image_log(self, log_id: int) -> dict[str, Any] | None: ...


class ModuleMediaGateway:
    @property
    def image_defaults(self) -> dict[str, Any]:
        return copy.deepcopy(images_simple._DEFAULTS)

    @property
    def xai_defaults(self) -> dict[str, Any]:
        section = config.DEFAULT_CONFIG.get("xaiOAuth") or {}
        return copy.deepcopy(section if isinstance(section, dict) else {})

    @property
    def data_dir(self) -> str:
        return str(config.DATA_DIR)

    def image_settings(self) -> dict[str, Any]:
        return images_simple.settings()

    def image_accounts(self) -> list[dict[str, Any]]:
        return images_simple.list_image_accounts(include_disabled=True)

    def image_log(self, log_id: int) -> dict[str, Any] | None:
        return image_db.get_log(log_id)


class ImageControl:
    def __init__(
        self,
        *,
        config_gateway: ConfigGateway | None = None,
        media_gateway: MediaGateway | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._config = config_gateway or ModuleConfigGateway()
        self._media = media_gateway or ModuleMediaGateway()
        self._audit_sink = audit_sink

    def _effective_from_root(self, root: dict[str, Any]) -> dict[str, Any]:
        value = self._media.image_defaults
        raw = root.get("images") or {}
        if isinstance(raw, dict):
            value.update(copy.deepcopy(raw))
        return value

    @staticmethod
    def _dto(value: dict[str, Any]) -> ImageSettings:
        stable = {
            "enabled": bool(value.get("enabled", True)),
            "cacheEnabled": bool(value.get("cacheEnabled", False)),
            "mainModel": str(value.get("mainModel") or ""),
            "toolModel": str(value.get("toolModel") or ""),
            "cachePath": str(value.get("cachePath") or ""),
            "cacheRetentionDays": int(value.get("cacheRetentionDays") or 0),
            "cacheMaxBytes": int(value.get("cacheMaxBytes") or 0),
        }
        return ImageSettings(
            enabled=stable["enabled"],
            cache_enabled=stable["cacheEnabled"],
            main_model=stable["mainModel"],
            tool_model=stable["toolModel"],
            cache_path=stable["cachePath"],
            cache_retention_days=stable["cacheRetentionDays"],
            cache_max_bytes=stable["cacheMaxBytes"],
            revision=revision_for(stable),
        )

    def get_settings(self, context: ManagementContext) -> ImageSettings:
        require(context, Capability.READ)
        return self._dto(self._media.image_settings())

    def settings_raw_direct(self, context: ManagementContext) -> dict[str, Any]:
        require(context, Capability.READ)
        return self._media.image_settings()

    def _validate_path(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw or "\x00" in raw:
            raise invalid_field("cachePath", "INVALID_PATH", "cachePath must not be empty")
        if not os.path.isabs(raw):
            root = (Path(self._media.data_dir) / raw).resolve()
            try:
                root.relative_to(Path(self._media.data_dir).resolve())
            except ValueError as exc:
                raise invalid_field("cachePath", "PATH_ESCAPE", "relative cachePath escapes data directory") from exc
        return raw

    def update_settings(
        self,
        context: ManagementContext,
        patch: dict[str, Any],
        *,
        expected_revision: str | None = None,
    ) -> ImageSettings:
        require(context, Capability.WRITE)
        value = copy.deepcopy(patch)
        for field in ("mainModel", "toolModel"):
            if field in value:
                normalized = str(value[field] or "").strip()
                if not normalized or len(normalized) > 128:
                    raise invalid_field(field, "INVALID_MODEL", "model must contain 1 to 128 characters")
                value[field] = normalized
        if "cachePath" in value:
            value["cachePath"] = self._validate_path(value["cachePath"])
        for field, high in (("cacheRetentionDays", 36500), ("cacheMaxBytes", 2**63 - 1)):
            if field in value:
                number = value[field]
                if not isinstance(number, int) or isinstance(number, bool) or not 0 <= number <= high:
                    raise invalid_field(field, "OUT_OF_RANGE", f"must be between 0 and {high}")

        def mutate(root: dict[str, Any]) -> None:
            current = self._dto(self._effective_from_root(root))
            ensure_revision(expected_revision, current.revision)
            root.setdefault("images", {}).update(copy.deepcopy(value))

        self._config.update(mutate)
        audit(self._audit_sink, context, action="images.settings.update", target="images")
        return self._dto(self._media.image_settings())

    def mutate_direct(self, context: ManagementContext, mutator) -> ImageSettings:
        require(context, Capability.WRITE)

        def mutate(root: dict[str, Any]) -> None:
            section = root.setdefault("images", {})
            mutator(section)

        self._config.update(mutate)
        audit(self._audit_sink, context, action="images.settings.update", target="images")
        return self._dto(self._media.image_settings())

    @staticmethod
    def _account(row: dict[str, Any]) -> ImageAccountState:
        stable = {
            "accountId": str(row.get("account_key") or ""),
            "email": str(row.get("email") or ""),
            "oauthEnabled": bool(row.get("enabled")),
            "imageEnabled": not bool(row.get("image_disabled")),
            "imageCooldownUntil": (
                rfc3339_utc(row.get("image_cooldown_until"))
                if row.get("image_cooldown_until") not in (None, "", 0, 0.0, "0")
                else None
            ),
            "missingAccountId": bool(row.get("missing_account_id")),
        }
        return ImageAccountState(
            account_id=stable["accountId"],
            email=stable["email"],
            oauth_enabled=stable["oauthEnabled"],
            image_enabled=stable["imageEnabled"],
            image_cooldown_until=stable["imageCooldownUntil"],
            missing_account_id=stable["missingAccountId"],
            revision=revision_for(stable),
        )

    def list_accounts(self, context: ManagementContext) -> tuple[ImageAccountState, ...]:
        require(context, Capability.READ)
        return tuple(self._account(row) for row in self._media.image_accounts())

    def accounts_raw_direct(self, context: ManagementContext) -> list[dict[str, Any]]:
        require(context, Capability.READ)
        return self._media.image_accounts()

    def get_account(self, context: ManagementContext, account_id: str) -> ImageAccountState:
        require(context, Capability.READ)
        for row in self._media.image_accounts():
            if str(row.get("account_key") or "") == account_id:
                return self._account(row)
        raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)

    @staticmethod
    def _account_aliases(account_id: str, email: str) -> set[str]:
        aliases = {account_id.strip().lower(), f"oauth:{account_id.strip()}".lower()}
        normalized_email = email.strip().lower()
        if normalized_email:
            aliases.update({normalized_email, f"openai:{normalized_email}"})
        return aliases

    def update_account(
        self,
        context: ManagementContext,
        account_id: str,
        *,
        enabled: bool,
        expected_revision: str | None = None,
    ) -> ImageAccountState:
        require(context, Capability.WRITE)
        current = self.get_account(context, account_id)
        ensure_revision(expected_revision, current.revision)
        aliases = self._account_aliases(current.account_id, current.email)

        def mutate(root: dict[str, Any]) -> None:
            section = root.setdefault("images", {})
            values = list(section.get("disabledAccounts") or [])
            if enabled:
                values = [item for item in values if str(item).strip().lower() not in aliases]
            elif not any(str(item).strip().lower() in aliases for item in values):
                values.append(current.account_id)
            section["disabledAccounts"] = values

        committed = self._config.update(mutate)
        committed_values = list((committed.get("images") or {}).get("disabledAccounts") or [])
        image_enabled = not any(str(item).strip().lower() in aliases for item in committed_values)
        audit(self._audit_sink, context, action="images.account.update", target=account_id)
        # The OAuth list adapter may be eventually consistent in production. Derive
        # the returned image flag and revision from the committed authoritative set.
        stable = {
            "accountId": current.account_id,
            "email": current.email,
            "oauthEnabled": current.oauth_enabled,
            "imageEnabled": image_enabled,
            "imageCooldownUntil": current.image_cooldown_until,
            "missingAccountId": current.missing_account_id,
        }
        return ImageAccountState(
            account_id=current.account_id,
            email=current.email,
            oauth_enabled=current.oauth_enabled,
            image_enabled=image_enabled,
            image_cooldown_until=current.image_cooldown_until,
            missing_account_id=current.missing_account_id,
            revision=revision_for(stable),
        )

    def toggle_account_direct(self, context: ManagementContext, account_id: str) -> None:
        require(context, Capability.WRITE)

        def mutate(root: dict[str, Any]) -> None:
            section = root.setdefault("images", {})
            values = list(section.get("disabledAccounts") or [])
            positions = {str(item).lower(): index for index, item in enumerate(values)}
            if account_id.lower() in positions:
                values.pop(positions[account_id.lower()])
            else:
                values.append(account_id)
            section["disabledAccounts"] = values

        self._config.update(mutate)
        audit(self._audit_sink, context, action="images.account.toggle", target=account_id)

    def cached_image_log(self, context: ManagementContext, log_id: int) -> CachedImageLog | None:
        require(context, Capability.READ)
        row = self._media.image_log(log_id)
        if not row:
            return None
        try:
            raw_paths = json.loads(row.get("cache_paths") or "[]")
        except Exception:
            raw_paths = []
        paths = tuple(
            item for item in raw_paths
            if isinstance(item, str) and os.path.exists(item)
        )
        return CachedImageLog(
            id=int(row.get("id") or log_id),
            action=str(row.get("action") or ""),
            account_email=str(row.get("account_email") or ""),
            paths=paths,
        )


class XaiMediaControl:
    def __init__(
        self,
        *,
        config_gateway: ConfigGateway | None = None,
        media_gateway: MediaGateway | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._config = config_gateway or ModuleConfigGateway()
        self._media = media_gateway or ModuleMediaGateway()
        self._audit_sink = audit_sink

    def _effective(self, root: dict[str, Any]) -> dict[str, Any]:
        defaults = self._media.xai_defaults
        raw = root.get("xaiOAuth") or {}
        if isinstance(raw, dict):
            defaults.update(copy.deepcopy(raw))
        return {
            "imageModels": string_list(defaults.get("imageModels")),
            "videoModels": string_list(defaults.get("videoModels")),
            "jobTtlSeconds": self._positive(defaults.get("videoJobTtlSeconds"), 10800),
            "requestTimeoutSeconds": self._positive(defaults.get("mediaRequestTimeoutSeconds"), 180),
        }

    @staticmethod
    def _positive(value: Any, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    @staticmethod
    def _dto(value: dict[str, Any]) -> XaiMediaSettings:
        stable = {
            "imageModels": string_list(value["imageModels"]),
            "videoModels": string_list(value["videoModels"]),
            "jobTtlSeconds": int(value["jobTtlSeconds"]),
            "requestTimeoutSeconds": int(value["requestTimeoutSeconds"]),
        }
        return XaiMediaSettings(
            image_models=tuple(stable["imageModels"]),
            video_models=tuple(stable["videoModels"]),
            job_ttl_seconds=stable["jobTtlSeconds"],
            request_timeout_seconds=stable["requestTimeoutSeconds"],
            revision=revision_for(stable),
        )

    def get_settings(self, context: ManagementContext) -> XaiMediaSettings:
        require(context, Capability.READ)
        return self._dto(self._effective(self._config.get()))

    def settings_raw_direct(self, context: ManagementContext) -> dict[str, Any]:
        require(context, Capability.READ)
        raw = self._config.get().get("xaiOAuth") or {}
        return raw if isinstance(raw, dict) else {}

    @staticmethod
    def validate_models(models: Any, field: str) -> list[str]:
        values = string_list(models)
        if len(values) > 50:
            raise invalid_field(field, "TOO_MANY_MODELS", "at most 50 models are allowed")
        for index, model in enumerate(values):
            if len(model) > 128:
                raise invalid_field(f"{field}[{index}]", "MODEL_TOO_LONG", "model must be at most 128 characters")
        return values

    def update_settings(
        self,
        context: ManagementContext,
        patch: dict[str, Any],
        *,
        expected_revision: str | None = None,
    ) -> XaiMediaSettings:
        require(context, Capability.WRITE)
        value = copy.deepcopy(patch)
        if "imageModels" in value:
            value["imageModels"] = self.validate_models(value["imageModels"], "imageModels")
        if "videoModels" in value:
            value["videoModels"] = self.validate_models(value["videoModels"], "videoModels")
        for field in ("jobTtlSeconds", "requestTimeoutSeconds"):
            if field in value:
                number = value[field]
                if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 2_147_483_647:
                    raise invalid_field(field, "OUT_OF_RANGE", "must be between 1 and 2147483647")

        def mutate(root: dict[str, Any]) -> None:
            current = self._dto(self._effective(root))
            ensure_revision(expected_revision, current.revision)
            section = root.get("xaiOAuth")
            if not isinstance(section, dict):
                section = {}
                root["xaiOAuth"] = section
            for field, item in value.items():
                raw_field = {
                    "jobTtlSeconds": "videoJobTtlSeconds",
                    "requestTimeoutSeconds": "mediaRequestTimeoutSeconds",
                }.get(field, field)
                section[raw_field] = copy.deepcopy(item)

        self._config.update(mutate)
        audit(self._audit_sink, context, action="xai.media-settings.update", target="xai-media")
        return self._dto(self._effective(self._config.get()))

    def set_raw_field(self, context: ManagementContext, key: str, value: Any) -> XaiMediaSettings:
        require(context, Capability.WRITE)

        def mutate(root: dict[str, Any]) -> None:
            section = root.get("xaiOAuth")
            if not isinstance(section, dict):
                section = {}
                root["xaiOAuth"] = section
            section[key] = copy.deepcopy(value)

        self._config.update(mutate)
        audit(self._audit_sink, context, action="xai.media-settings.update", target=key)
        return self._dto(self._effective(self._config.get()))

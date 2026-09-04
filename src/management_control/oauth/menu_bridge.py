"""Stable OAuth facade for Telegram menu adapters."""

from __future__ import annotations

from src import (
    model_metadata,
    models_discovery as _models_discovery,
    notifier,
    oauth_errors,
    oauth_ids as _oauth_ids,
    status_monitor,
    update_checker,
)
from src.management_auth.principal import AuthMethod, ManagementPrincipal
from src.management_control.context import ManagementContext
from src.models_discovery import ModelsDiscoveryError
from src.oauth import antigravity as antigravity_provider
from src.oauth import openai_import as _openai_import
from src.oauth.openai_import import OpenAIImportParseError

from .control import OAuthControl


control = OAuthControl()


def telegram_context(chat_id: int) -> ManagementContext:
    return ManagementContext(
        request_id=f"telegram:{chat_id}",
        actor=ManagementPrincipal.administrator(
            subject_id=f"telegram:{chat_id}",
            auth_method=AuthMethod.TELEGRAM_ADMIN,
        ),
    )


def account_key(account: dict) -> str:
    return _oauth_ids.account_key(account)


def openai_account_identity_parts(account: dict):
    return _oauth_ids.openai_account_identity_parts(account)


def openai_workspace_id(account: dict) -> str:
    return _oauth_ids.openai_workspace_id(account)


def split_account_key(value: str):
    return _oauth_ids.split_account_key(value)


async def discover_models(*args, **kwargs):
    return await _models_discovery.discover_models(*args, **kwargs)


def parse_openai_import_payload(*args, **kwargs):
    return _openai_import.parse_openai_import_payload(*args, **kwargs)

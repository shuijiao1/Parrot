"""Narrow compatibility bridge while Telegram rendering remains in its menus.

The bridge deliberately lives on the control side of the dependency boundary. It
resolves domain attributes at call time so existing fake-boundary tests continue to
patch the authoritative modules rather than private copies.
"""

from __future__ import annotations

from src import (
    affinity as _affinity,
    config as _config,
    cooldown as _cooldown,
    load_balancing as _load_balancing,
    log_db as _log_db,
    model_metadata as _model_metadata,
    notifier as _notifier,
    oauth_errors as _oauth_errors,
    oauth_manager as _oauth_manager,
    state_db as _state_db,
    status_monitor as _status_monitor,
    update_checker as _update_checker,
)
from src.cursor_bridge import catalog as _cursor_model_catalog
from src.models_discovery import ModelsDiscoveryError
from src import models_discovery as _models_discovery
from src.oauth import antigravity as _antigravity_provider
from src.oauth import cursor as _cursor_provider
from src.oauth import openai as _openai_provider
from src.oauth import xai as _xai_provider
from src.oauth import openai_import as _openai_import
from src.oauth.openai_import import OpenAIImportParseError
from src import oauth_ids as _oauth_ids
from src.management_auth.principal import AuthMethod, ManagementPrincipal
from src.management_control.context import ManagementContext

from .control import OAuthControl


class _ModuleProxy:
    __slots__ = ("_module",)

    def __init__(self, module) -> None:
        object.__setattr__(self, "_module", module)

    def __getattr__(self, name: str):
        return getattr(self._module, name)

    def __setattr__(self, name: str, value) -> None:
        setattr(self._module, name, value)

    def __delattr__(self, name: str) -> None:
        delattr(self._module, name)


config = _ModuleProxy(_config)
oauth_manager = _ModuleProxy(_oauth_manager)
cooldown = _ModuleProxy(_cooldown)
affinity = _ModuleProxy(_affinity)
load_balancing = _ModuleProxy(_load_balancing)
log_db = _ModuleProxy(_log_db)
model_metadata = _ModuleProxy(_model_metadata)
notifier = _ModuleProxy(_notifier)
oauth_errors = _ModuleProxy(_oauth_errors)
state_db = _ModuleProxy(_state_db)
status_monitor = _ModuleProxy(_status_monitor)
update_checker = _ModuleProxy(_update_checker)
cursor_model_catalog = _ModuleProxy(_cursor_model_catalog)
openai_provider = _ModuleProxy(_openai_provider)
xai_provider = _ModuleProxy(_xai_provider)
cursor_provider = _ModuleProxy(_cursor_provider)
antigravity_provider = _ModuleProxy(_antigravity_provider)
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

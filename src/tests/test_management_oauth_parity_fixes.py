from __future__ import annotations

import asyncio
import copy
import inspect
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from src.management_control import ManagementError, ManagementErrorCode
from src.management_control.oauth import (
    CompleteOAuthLoginCommand,
    CreateOAuthAccountCommand,
    ManualCredential,
    OAuthImportDecision,
    OAuthProvider,
)
from src.tests.management_oauth_fakes import build_control
from src.tests.test_management_oauth_api import ACCOUNT_ID, INVALID_ID


def test_real_usage_snapshot_signature_and_backend_call_have_no_force_keyword(monkeypatch):
    from src import oauth_manager
    from src.management_control.oauth import OAuthBackend

    assert "force" not in inspect.signature(oauth_manager.fetch_usage_snapshot).parameters
    calls = []

    async def strict_snapshot(account_id, *, usage_timeout_s=None, detail_timeout_s=None):
        calls.append((account_id, usage_timeout_s, detail_timeout_s))
        return {"five_hour": {"utilization": 1.0}}

    monkeypatch.setattr(oauth_manager, "fetch_usage_snapshot", strict_snapshot)
    result = asyncio.run(OAuthBackend().fetch_usage_snapshot("openai:strict@example.test:ws"))
    assert result["five_hour"]["utilization"] == 1.0
    assert calls == [("openai:strict@example.test:ws", None, None)]


def test_bulk_usage_refresh_isolates_each_account_failure_and_continues():
    control, backend = build_control()
    tail_id = "claude:tail@example.test"
    backend.accounts.append({
        "_id": tail_id,
        "provider": "claude",
        "email": "tail@example.test",
        "access_token": "tail-access",
        "refresh_token": "tail-refresh",
        "models": [],
    })
    backend.usage_failures.add(INVALID_ID)

    result = control._refresh_usage_worker(
        [ACCOUNT_ID, INVALID_ID, tail_id], continue_on_error=True,
    )

    assert backend.usage_fetches == [ACCOUNT_ID, INVALID_ID, tail_id]
    assert result == {
        "accounts": [
            {"accountId": ACCOUNT_ID, "status": "refreshed"},
            {"accountId": INVALID_ID, "status": "failed"},
            {"accountId": tail_id, "status": "refreshed"},
        ],
        "total": 3,
        "refreshed": 2,
        "failed": 1,
    }
    assert backend.quota_evaluations == [ACCOUNT_ID, tail_id]
    assert tail_id in backend.quota


@pytest.mark.parametrize("provider", [OAuthProvider.XAI, OAuthProvider.CURSOR])
@pytest.mark.parametrize("old_has_subject", [False, True])
def test_xai_cursor_legacy_email_guard_rejects_subject_presence_migration(
    provider, old_has_subject,
):
    from src.management_control.oauth.menu_bridge import telegram_context

    control, backend = build_control()
    email = f"legacy-{provider.value}@example.test"
    old = {
        "_id": f"{provider.value}:{'old-subject' if old_has_subject else email}",
        "provider": provider.value,
        "type": provider.value,
        "email": email,
        "access_token": "old-access",
        "refresh_token": "old-refresh",
        "models": [],
    }
    if old_has_subject:
        old.update(subject="old-subject", sub="old-subject")
    backend.accounts.append(old)
    incoming_subject = None if old_has_subject else "new-subject"
    credential = ManualCredential(
        provider,
        email,
        "new-access",
        "new-refresh",
        identity_subject=incoming_subject,
    )
    before = copy.deepcopy(backend.accounts)

    with pytest.raises(ManagementError) as caught:
        control.create_account(
            telegram_context(42), CreateOAuthAccountCommand(credential),
        )

    assert caught.value.code is ManagementErrorCode.IDENTITY_CONFLICT
    assert caught.value.fields[0].code == "LEGACY_IDENTITY_MIGRATION"
    assert backend.accounts == before
    assert backend.model_sync_started == []


def test_create_login_complete_and_replace_each_run_shared_post_save_effects_once():
    from src.management_control.oauth.menu_bridge import telegram_context

    context = telegram_context(42)
    control, backend = build_control()
    first = ManualCredential(
        OAuthProvider.OPENAI,
        "post-save@example.test",
        "first-access",
        "first-refresh",
        workspace_id="post-save-workspace",
    )
    created = control.create_account(context, CreateOAuthAccountCommand(first))
    assert created.status == "created"
    assert backend.model_sync_started == [created.account_id]
    assert backend.usage_fetches == [created.account_id]
    assert backend.quota_evaluations == [created.account_id]

    backend.model_sync_started.clear()
    backend.usage_fetches.clear()
    backend.quota_evaluations.clear()
    second = ManualCredential(
        OAuthProvider.OPENAI,
        "post-save@example.test",
        "second-access",
        "second-refresh",
        workspace_id="post-save-workspace",
    )
    with pytest.raises(ManagementError) as conflict:
        control.create_account(context, CreateOAuthAccountCommand(second))
    token = conflict.value.plan_token
    assert backend.model_sync_started == []
    replaced = control.create_account(
        context, CreateOAuthAccountCommand(second, replace_plan_token=token),
    )
    assert replaced.status == "replaced"
    assert backend.model_sync_started == [created.account_id]
    assert backend.usage_fetches == [created.account_id]
    assert backend.quota_evaluations == [created.account_id]

    login_control, login_backend = build_control()
    flow = login_control.start_login_flow(context, OAuthProvider.OPENAI)
    state = parse_qs(urlparse(flow.auth_url).query)["state"][0]
    completed = login_control.complete_login_flow(
        context,
        flow.flow_id,
        flow.flow_secret,
        CompleteOAuthLoginCommand(code="code", state=state),
    )
    assert login_backend.model_sync_started == [completed.account_id]
    assert login_backend.usage_fetches == [completed.account_id]
    assert login_backend.quota_evaluations == [completed.account_id]

    telegram_source = Path("src/telegram/menus/oauth_menu.py").read_text(encoding="utf-8")
    assert "oauth_control.start_account_model_refresh(" not in telegram_source
    assert telegram_source.count("_evaluate_quota_action(") == 1


def test_telegram_deferred_renderer_runs_the_same_post_save_owner_once():
    from src.management_control.oauth.menu_bridge import telegram_context

    context = telegram_context(42)
    control, backend = build_control()
    entry = {
        "provider": "openai",
        "type": "openai",
        "email": "telegram-post-save@example.test",
        "workspace_id": "telegram-workspace",
        "chatgpt_account_id": "telegram-workspace",
        "access_token": "telegram-access",
        "refresh_token": "telegram-refresh",
        "models": [],
    }
    account_id = "openai:telegram-post-save@example.test:telegram-workspace"

    saved = control.add_account_entry(
        context, entry, defer_post_save=True,
    )
    assert saved["status"] == "added"
    assert "_post_save" not in saved
    assert backend.model_sync_started == []
    assert backend.usage_fetches == []
    assert backend.quota_evaluations == []

    effects = control.run_post_save_account_effects(context, account_id, entry)
    assert effects["model_sync_future"] is not None
    assert backend.model_sync_started == [account_id]
    assert backend.usage_fetches == [account_id]
    assert backend.quota_evaluations == [account_id]


def test_import_and_invalid_delete_recheck_and_mutate_inside_one_batch_cas():
    from src.management_control.oauth.menu_bridge import telegram_context

    context = telegram_context(42)
    control, backend = build_control()
    candidates = [
        {
            "provider": "openai",
            "type": "openai",
            "email": f"batch-{index}@example.test",
            "refresh_token": f"refresh-{index}-12345678901234567890",
        }
        for index in range(2)
    ]
    preview = control.preview_import(
        context, format="openai", payload=json.dumps(candidates),
    )
    concurrent_id = "claude:interleaved@example.test"
    backend.interleave_once = lambda: backend.accounts.append({
        "_id": concurrent_id,
        "provider": "claude",
        "email": "interleaved@example.test",
        "access_token": "a",
        "refresh_token": "r",
        "models": [],
    })
    decisions = tuple(
        OAuthImportDecision(item.candidate_id, "overwrite")
        for item in preview.candidates
    )
    with pytest.raises(ManagementError) as stale_import:
        control.commit_import(
            context, preview.import_id, preview.import_secret, decisions,
        )
    assert stale_import.value.code is ManagementErrorCode.REVISION_CONFLICT
    assert all(
        backend.get_account(
            f"openai:batch-{index}@example.test:import-batch-{index}"
        ) is None
        for index in range(2)
    )
    assert backend.get_account(concurrent_id) is not None

    second_invalid = "claude:invalid-two@example.test"
    backend.accounts.append({
        "_id": second_invalid,
        "provider": "claude",
        "email": "invalid-two@example.test",
        "access_token": "a",
        "refresh_token": "r",
        "disabled_reason": "auth_error",
        "models": [],
    })
    deletion = control.plan_invalid_deletion(context, [INVALID_ID, second_invalid])
    backend.interleave_once = lambda: backend.get_account(second_invalid).__setitem__(
        "concurrent", True,
    )
    with pytest.raises(ManagementError) as stale_delete:
        control.delete_invalid_accounts(context, deletion.plan_token)
    assert stale_delete.value.code is ManagementErrorCode.REVISION_CONFLICT
    assert backend.get_account(INVALID_ID) is not None
    assert backend.get_account(second_invalid)["concurrent"] is True


@pytest.mark.parametrize(
    ("provider", "expected_note", "other_note"),
    [
        (
            "cursor",
            "⚠️ 新额度快照保存失败，可稍后手动刷新。",
            "⚠️ 新额度快照获取失败，可稍后手动刷新。",
        ),
        (
            "openai",
            "⚠️ 新额度快照获取失败，可稍后手动刷新。",
            "⚠️ 新额度快照保存失败，可稍后手动刷新。",
        ),
    ],
)
def test_tg_overwrite_failure_note_keeps_provider_specific_frozen_wording(
    monkeypatch, provider, expected_note, other_note,
):
    from src.telegram import ui
    from src.telegram.menus import oauth_menu

    account_id = f"{provider}:overwrite-identity"
    entry = {
        "provider": provider,
        "email": f"{provider}@example.test",
        "access_token": "new-access",
        "refresh_token": "new-refresh",
    }
    state = {
        "entry": entry,
        "target_key": account_id,
        "provider": provider,
        "usage": {"window": "fake"},
    }
    owners = []
    edits = []
    monkeypatch.setattr(oauth_menu, "_overwrite_state", lambda *_args, **_kwargs: state)
    monkeypatch.setattr(
        oauth_menu.oauth_control,
        "replace_account_entry",
        lambda *_args, **_kwargs: {"status": "replaced"},
    )
    monkeypatch.setattr(
        oauth_menu,
        "_foreground_account_model_sync",
        lambda *_args, **_kwargs: (
            owners.append(account_id),
            {"post_save": {"usage_error": RuntimeError("injected usage failure")}},
        )[1],
    )
    monkeypatch.setattr(ui, "answer_cb", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        ui,
        "edit",
        lambda _chat, _message, text, **_kwargs: edits.append(text),
    )

    oauth_menu.on_oauth_overwrite_confirm(42, 100, "cb-confirm", "nonce")

    assert owners == [account_id]
    assert len(edits) == 1
    assert expected_note in edits[0]
    assert other_note not in edits[0]

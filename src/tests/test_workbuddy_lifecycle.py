"""Real manager/control lifecycle; temporary config, fixture tokens, no external I/O."""
from __future__ import annotations

import asyncio
import copy
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from src import config, oauth_manager as om, state_db
from src.management_auth.principal import AuthMethod, ManagementPrincipal
from src.management_control.context import ManagementContext
from src.management_control.errors import ManagementError
from src.management_control.oauth import CompleteOAuthLoginCommand, OAuthControl, OAuthProvider
from src.oauth.workbuddy import auth, common, runtime


@pytest.fixture
def account(monkeypatch):
    state_db.init()
    before = copy.deepcopy(config.get())
    monkeypatch.delenv("PARROT_NO_REFRESH", raising=False)
    runtime._refresh_states.clear()
    entry = auth.normalize_credential({"realm": "cn", "uid": "fixture-" + uuid.uuid4().hex,
        "access_token": "fixture-at", "refresh_token": "fixture-rt", "nickname": "样本"})
    config.update(lambda c: c.update(oauthAccounts=[], channels=[]))
    om.add_account(entry)
    key = om.get_account_key(entry)
    yield key
    runtime._refresh_states.clear()
    config.update(lambda c: (c.clear(), c.update(before)))


def context(name="fixture-admin"):
    return ManagementContext("fixture-request", ManagementPrincipal.administrator(
        subject_id=name, auth_method=AuthMethod.MANAGEMENT_KEY))


@pytest.fixture
def control(monkeypatch):
    clock = [datetime.now(timezone.utc)]
    result = OAuthControl(clock=lambda: clock[0])
    monkeypatch.setattr(result, "_post_save_account_effects", lambda *a, **k: {})
    monkeypatch.setattr(result.backend, "workbuddy_start_login", lambda: {
        "realm": "cn", "state": "fixture-state", "auth_url": "https://www.codebuddy.cn/login", "status": "pending"})
    return result, clock


@pytest.mark.parametrize("reason", ["user", "quota", "auth_error", None])
def test_exact_overwrite_preserves_settings_and_identity(account, reason):
    config.update(lambda c: c["oauthAccounts"][0].update(
        label="保留备注", workbuddy_auto_checkin=True, maxConcurrent=7,
        models=["glm-fixture"], disabledModels=["glm-fixture"],
        account_model_catalog={"models": [{"id": "glm-fixture"}]},
        enabled=reason is None, disabled_reason=reason, extension={"keep": True}))
    old = copy.deepcopy(om.get_account(account))
    incoming = dict(old, access_token="new-at", refresh_token="new-rt", nickname="新昵称",
        label="登录默认备注", workbuddy_auto_checkin=False, models=[], disabledModels=[],
        maxConcurrent=1, account_model_catalog={})
    incoming.pop("email", None)
    result = om.replace_exact_identity(account, incoming, expected_account=old)
    assert result["status"] == "replaced"
    saved = om.get_account(account)
    assert saved["access_token"] == "new-at" and saved["nickname"] == "新昵称"
    for field in ("label", "workbuddy_auto_checkin", "models", "disabledModels", "maxConcurrent", "account_model_catalog", "extension"):
        assert saved[field] == old[field]
    assert saved["enabled"] is (reason in {None, "auth_error"})
    assert saved["disabled_reason"] == (None if reason == "auth_error" else reason)


def test_replacement_rejects_stale_candidate(account):
    old = copy.deepcopy(om.get_account(account))
    config.update(lambda c: c["oauthAccounts"][0].update(label="并发编辑"))
    assert om.replace_exact_identity(account, dict(old, access_token="new"), expected_account=old)["status"] == "revision_conflict"
    assert om.get_account(account)["access_token"] == "fixture-at"


def test_refresh_unknown_expiry_coalesces_and_keeps_rt(account, monkeypatch):
    calls = []
    def refresh(*a, **k):
        calls.append(1)
        time.sleep(.02)
        return {"access_token": "new-at"}
    monkeypatch.setattr(auth, "refresh_sync", refresh)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: om._refresh_sync_locked(account, False), range(6)))
    assert results == ["new-at"] * 6 and len(calls) == 1
    saved = om.get_account(account)
    assert saved["refresh_token"] == "fixture-rt" and saved["expired"] == ""
    assert not runtime.refresh_due(saved, account)


def test_refresh_save_failure_retries_only_persistence_even_when_old_expiry_healthy(account, monkeypatch):
    config.update(lambda c: c["oauthAccounts"][0].update(expired=auth.utc_text(time.time() + 7200)))
    calls = []
    monkeypatch.setattr(auth, "refresh_sync", lambda *a, **k: (calls.append(1) or {"access_token": "rotated-at", "refresh_token": "rotated-rt"}))
    save = om._save_token_fields
    attempts = []
    def fail_once(*a, **k):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("fixture persistence failure")
        return save(*a, **k)
    monkeypatch.setattr(om, "_save_token_fields", fail_once)
    with pytest.raises(common.WorkBuddyError, match="save_failed_retry_save"):
        om._refresh_sync_locked(account, True)
    assert asyncio.run(om.ensure_valid_token(account)) == "rotated-at"
    assert len(calls) == 1 and len(attempts) == 2
    assert om.get_account(account)["refresh_token"] == "rotated-rt"


def test_failed_refresh_backs_off_and_protection_never_calls_provider(account, monkeypatch):
    calls = []
    def fail(*a, **k):
        calls.append(1)
        raise common.WorkBuddyError("refresh", status=503)
    monkeypatch.setattr(auth, "refresh_sync", fail)
    for _ in range(2):
        with pytest.raises(common.WorkBuddyError):
            om._refresh_sync_locked(account, False)
    assert len(calls) == 1
    monkeypatch.setenv("PARROT_NO_REFRESH", "1")
    assert asyncio.run(om.force_refresh(account)) == "fixture-at"
    assert asyncio.run(om.proactive_refresh_once()) == {account: "skipped:protected"}
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["delete", "replace"])
def test_refresh_cannot_overwrite_new_identity_generation(account, monkeypatch, change):
    def rotate(*a, **k):
        if change == "delete":
            config.update(lambda c: c.update(oauthAccounts=[]))
        else:
            config.update(lambda c: c["oauthAccounts"][0].update(access_token="new-login-at", refresh_token="new-login-rt"))
        return {"access_token": "old-flight-at", "refresh_token": "old-flight-rt"}
    monkeypatch.setattr(auth, "refresh_sync", rotate)
    with pytest.raises(common.WorkBuddyError, match="stale_generation"):
        om._refresh_sync_locked(account, True)
    if change == "replace":
        assert om.get_account(account)["refresh_token"] == "new-login-rt"
    assert account not in runtime._refresh_states


def test_expired_unsaved_rotation_never_replays_old_refresh_token(account, monkeypatch):
    current = om.get_account(account)
    runtime._refresh_states[account] = runtime._RefreshState(runtime.credential_fingerprint(current),
        pending={"access_token": "unsaved"}, pending_until=0)
    monkeypatch.setattr(auth, "refresh_sync", lambda *a, **k: pytest.fail("must not rotate"))
    for _ in range(2):
        with pytest.raises(common.WorkBuddyError, match="save_candidate_expired_relogin"):
            om._refresh_sync_locked(account, True)
    assert runtime._refresh_states[account].pending is None


def observation(account, remaining=0, **values):
    acc = om.get_account(account)
    return {"workbuddy": {"realm": "cn", "complete": True, "fetched_at": time.time() * 1000,
        "credential_fingerprint": runtime.credential_fingerprint(acc),
        "credits": {"scope": "personal", "reliable": True, "remaining": remaining}, **values}}


def test_credits_disable_only_trustworthy_zero_and_recover_from_fresh_positive(account):
    assert om.evaluate_and_toggle_by_usage(account, observation(account, 1), fresh=True)["action"] == "kept_enabled"
    assert om.evaluate_and_toggle_by_usage(account, observation(account), fresh=True)["action"] == "disabled"
    assert om.get_account(account)["disabled_until"] is None
    assert om.evaluate_and_toggle_by_usage(account, observation(account, 10), fresh=False)["action"] == "noop_unknown"
    assert om.evaluate_and_toggle_by_usage(account, observation(account, 10), fresh=True)["action"] == "resumed"


@pytest.mark.parametrize("values", [
    {"complete": False}, {"fetched_at": 1}, {"realm": "global"},
    {"credits": {"scope": "personal", "reliable": False, "remaining": 0}},
    {"credits": {"scope": "enterprise", "reliable": True, "remaining": 0}},
    {"credential_fingerprint": "old-generation"},
])
def test_partial_stale_wrong_scope_never_disables(account, values):
    assert om.evaluate_and_toggle_by_usage(account, observation(account, **values), fresh=True)["action"].startswith("noop_")
    assert om.get_account(account)["enabled"]


@pytest.mark.parametrize("reason", ["user", "auth_error"])
def test_credit_recovery_never_revives_manual_or_auth_disable(account, reason):
    om.set_enabled(account, False, reason=reason)
    assert om.evaluate_and_toggle_by_usage(account, observation(account, 10), fresh=True)["action"] == "noop_" + reason
    assert not om.get_account(account)["enabled"]


def test_flow_pending_ready_actor_guard_complete_and_double_submit(account, control, monkeypatch):
    ctl, clock = control
    flow = ctl.start_login_flow(context(), OAuthProvider.WORKBUDDY)
    calls = []
    def poll(payload):
        calls.append(1)
        if len(calls) >= 2:
            payload.update(status="ready", entry=dict(om.get_account(account), uid="new-uid"))
    monkeypatch.setattr(ctl.backend, "workbuddy_poll_login", poll)
    for _ in range(2):
        assert ctl.poll_login_flow(context(), flow.flow_id, flow.flow_secret).status == "pending"
    assert len(calls) == 1
    with pytest.raises(ManagementError):
        ctl.poll_login_flow(context("other"), flow.flow_id, flow.flow_secret)
    with pytest.raises(ManagementError):
        ctl.complete_login_flow(context(), flow.flow_id, flow.flow_secret, CompleteOAuthLoginCommand(completed=True))
    clock[0] += timedelta(seconds=3)
    ready = ctl.poll_login_flow(context(), flow.flow_id, flow.flow_secret)
    assert ready.status == "completed" and "fixture-at" not in repr(ready)
    assert om.get_account(ready.account_id) is not None
    result = ctl.complete_login_flow(context(), flow.flow_id, flow.flow_secret, CompleteOAuthLoginCommand(completed=True))
    assert result.status == "created"
    assert ctl.complete_login_flow(context(), flow.flow_id, flow.flow_secret, CompleteOAuthLoginCommand(completed=True)) == result
    with pytest.raises(ManagementError):
        ctl.complete_login_flow(context("other"), flow.flow_id, flow.flow_secret, CompleteOAuthLoginCommand(completed=True))


def test_flow_overlap_cancel_and_expiry(account, control, monkeypatch):
    ctl, clock = control
    monkeypatch.setattr(ctl.backend, "workbuddy_poll_login", lambda p: None)
    flow = ctl.start_login_flow(context(), OAuthProvider.WORKBUDDY)
    with ctl._flows.workbuddy.lease(context().actor.subject_id, flow.flow_id, flow.flow_secret):
        with pytest.raises(ManagementError):
            ctl.poll_login_flow(context(), flow.flow_id, flow.flow_secret)
    ctl.cancel_login_flow(context(), flow.flow_id, flow.flow_secret)
    ctl.cancel_login_flow(context(), flow.flow_id, flow.flow_secret)  # idempotent
    assert ctl.poll_login_flow(context(), flow.flow_id, flow.flow_secret).status == "cancelled"
    with pytest.raises(ManagementError):
        ctl.cancel_login_flow(context("other"), flow.flow_id, flow.flow_secret)
    flow = ctl.start_login_flow(context(), OAuthProvider.WORKBUDDY)
    clock[0] += timedelta(seconds=301)
    assert ctl.poll_login_flow(context(), flow.flow_id, flow.flow_secret).status == "expired"
    ctl.cancel_login_flow(context(), flow.flow_id, flow.flow_secret)


def test_flow_same_identity_auto_updates_authorization_and_preserves_user_state(account, control, monkeypatch):
    ctl, clock = control
    om.set_enabled(account, False, reason="user")
    config.update(lambda c: c["oauthAccounts"][0].update(label="保留备注", models=["selected"],
        disabledModels=["selected"], maxConcurrent=7, workbuddy_auto_checkin=True))
    old = copy.deepcopy(om.get_account(account))
    monkeypatch.setattr(ctl.backend, "workbuddy_poll_login", lambda p: p.update(status="ready", entry=dict(old,
        access_token="login-at", label="新登录名称", models=[], disabledModels=[], maxConcurrent=0, enabled=True)))
    flow = ctl.start_login_flow(context(), OAuthProvider.WORKBUDDY)
    result = ctl.poll_login_flow(context(), flow.flow_id, flow.flow_secret)
    assert result.status == "completed" and result.save_status == "replaced"
    assert om.get_account(account)["access_token"] == "login-at"
    for key in ("label", "models", "disabledModels", "maxConcurrent", "enabled", "disabled_reason", "workbuddy_auto_checkin"):
        assert om.get_account(account)[key] == old[key]
    assert ctl.complete_login_flow(context(), flow.flow_id, flow.flow_secret, CompleteOAuthLoginCommand(completed=True)).account_id == account


def test_public_snapshot_allowlist_never_leaks_credentials(account):
    row = {"raw_data": json.dumps({"workbuddy": {
        "access_token": "secret", "errors": {"credits": {"kind": "network", "message": "secret"}},
        "credits": {"remaining": 10, "refresh_token": "secret"},
        "packages": [{"name": "pack", "uid": "secret"}], "credential_fingerprint": "secret"}})}
    result = runtime.public_snapshot(om.get_account(account), row)
    assert "secret" not in json.dumps(result)
    assert result["credits"]["remaining"] == 10

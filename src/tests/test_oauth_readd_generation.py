"""Delete/re-add incarnation isolation: fixture credentials, no live OAuth I/O."""
from __future__ import annotations

import asyncio
import copy
import uuid
from types import SimpleNamespace

import pytest

from src import affinity, channel_state, concurrency, config, cooldown, failover
from src import oauth_manager as om, scorer, state_db
from src.channel import registry
from src.oauth.workbuddy import auth, common, runtime


@pytest.fixture
def clean_accounts(monkeypatch):
    before = copy.deepcopy(config.get())
    monkeypatch.delenv("PARROT_NO_REFRESH", raising=False)
    state_db.init(); scorer.init(); cooldown.init(); affinity.init(); affinity.client_init()
    config.update(lambda c: c.update(oauthAccounts=[], channels=[]))
    yield
    config.update(lambda c: (c.clear(), c.update(before)))
    registry.rebuild_from_config()


def entry_for(provider):
    suffix = uuid.uuid4().hex
    entry = {"provider": provider, "email": f"{suffix}@example.test", "access_token": "fixture-at",
             "refresh_token": "fixture-rt", "models": ["fixture-model"], "enabled": True,
             "expired": "2099-01-01T00:00:00Z"}
    if provider == "openai":
        entry["chatgpt_account_id"] = "ws-" + suffix
    elif provider in {"cursor", "xai"}:
        entry["subject"] = suffix
    elif provider == "antigravity":
        entry["project_id"] = "project-" + suffix
    elif provider == "workbuddy":
        entry.update(uid=suffix, realm="cn")
    return entry


def add(entry):
    om.add_account(entry)
    key = om.get_account_key(entry)
    registry.rebuild_from_config()
    return key, registry.get_channel("oauth:" + key)


def remove(key, mode):
    if mode == "batch":
        om.set_enabled(key, False, reason="auth_error")
        expected = copy.deepcopy(om.get_account(key))
        assert om.delete_invalid_accounts_batch_if_unchanged([(key, expected)])["status"] == "deleted"
    else:
        om.delete_account(key)


@pytest.mark.parametrize("provider", ["claude", "openai", "xai", "cursor", "antigravity", "workbuddy"])
@pytest.mark.parametrize("mode", ["single", "batch"])
@pytest.mark.asyncio
async def test_readd_routes_immediately_and_old_effects_cannot_pollute_new(clean_accounts, provider, mode):
    key, old = add(entry_for(provider))
    saved = copy.deepcopy(om.get_account(key))
    logical, old_state = old.key, channel_state.effect_key(old)
    config.update(lambda c: c.setdefault("concurrency", {}).update(enabled=True, defaultMaxConcurrent=1))
    assert await concurrency.try_acquire(old_state)
    remove(key, mode)
    # Deliberately reuse the exact credentials AND the copied generationId.
    assert om.add_account_if_identity_absent(saved)["status"] == "added"
    registry.rebuild_from_config()
    new = registry.get_channel(logical)
    new_state = channel_state.effect_key(new)
    assert old_state != new_state and channel_state.is_deleted(old_state)
    assert not channel_state.is_deleted(logical)
    registry.rebuild_from_config()
    assert channel_state.effect_key(registry.get_channel(logical)) == new_state
    assert await concurrency.try_acquire(new_state)
    assert not await concurrency.try_acquire(old_state)
    assert await concurrency.acquire_from_candidates([(old_state, "stale")], .05) is None
    concurrency.release(old_state)
    assert concurrency._slots[new_state].in_flight == 1

    scorer.record_success(old_state, "late", 1, 2, 3)
    scorer.record_failure(old_state, "late", 1)
    cooldown.record_error(old_state, "late", "stale")
    affinity.upsert("late-" + key, old_state, "late")
    affinity.client_upsert("late-" + key, old_state, "late")
    state_db.quota_save(key, {"five_hour_util": 99}, expected_state_key=old_state)
    state_db.quota_patch_passive(key, {"seven_day_util": 99}, expected_state_key=old_state)
    state_db.quota_save_openai_snapshot(key, {"primary_used_pct": 99}, expected_state_key=old_state)
    assert not om._save_token_fields(key, {"access_token": "stale-at"}, expected_state_key=old_state)
    assert om.evaluate_and_toggle_by_usage(key, {"five_hour": {"utilization": 100}},
                                          expected_state_key=old_state)["action"] == "noop_stale"
    assert scorer.get_stats(logical, "late") is None
    assert cooldown.get_state(logical, "late") is None
    assert affinity.get("late-" + key) is None
    assert affinity.client_get("late-" + key) is None
    assert state_db.quota_load(key) is None
    assert om.get_account(key)["access_token"] == saved["access_token"]
    with pytest.raises(ValueError, match="generation was deleted"):
        await om.ensure_channel_token(old)
    with pytest.raises(ValueError, match="generation was deleted"):
        await om.force_refresh(key, expected_state_key=old_state)

    scorer.record_success(new_state, "fresh", 1, 2, 3)
    affinity.upsert("fresh-" + key, new_state, "fresh")
    state_db.quota_save(key, {"five_hour_util": 10}, expected_state_key=new_state)
    assert scorer.get_stats(logical, "fresh") is not None
    assert affinity.get("fresh-" + key)["channel_key"] == logical
    assert state_db.quota_load(key)["five_hour_util"] == 10
    concurrency.release(new_state)


@pytest.mark.parametrize("mode", ["single", "batch"])
def test_failed_delete_restores_only_its_existing_incarnation(clean_accounts, monkeypatch, mode):
    key, old = add(entry_for("workbuddy"))
    old_state = old.state_key
    if mode == "batch":
        om.set_enabled(key, False, reason="auth_error")
    expected = copy.deepcopy(om.get_account(key))
    monkeypatch.setattr(config, "_write_atomic", lambda _: (_ for _ in ()).throw(OSError("fixture write failure")))
    with pytest.raises(OSError, match="fixture write failure"):
        if mode == "batch":
            om.delete_invalid_accounts_batch_if_unchanged([(key, expected)])
        else:
            om.delete_account(key)
    assert om.get_account(key) == expected
    assert not channel_state.is_deleted(old_state)
    assert om.account_state_key(om.get_account(key)) == old_state
    monkeypatch.undo()


def test_workbuddy_rotated_response_after_same_credentials_readd_is_discarded(clean_accounts, monkeypatch):
    key, old = add(entry_for("workbuddy"))
    saved = copy.deepcopy(om.get_account(key))
    def refresh(*args, **kwargs):
        om.delete_account(key)
        om.add_account(saved)
        return {"access_token": "retired-at", "refresh_token": "retired-rt", "expires_in": 3600}
    monkeypatch.setattr(auth, "refresh_sync", refresh)
    with pytest.raises(common.WorkBuddyError) as caught:
        om._refresh_sync_locked(key, True)
    assert caught.value.kind == "stale_generation"
    assert om.get_account(key)["access_token"] == saved["access_token"]
    assert om.get_account(key)["generationId"] != saved["generationId"]


@pytest.mark.asyncio
async def test_late_access_quota_fetch_cannot_recreate_or_disable_readded_account(clean_accounts, monkeypatch):
    key, old = add(entry_for("claude"))
    saved = copy.deepcopy(om.get_account(key))
    config.update(lambda c: c.setdefault("quotaMonitor", {}).update(enabled=False, accessRefreshThrottleSeconds=0))
    async def fetch(*args, **kwargs):
        om.delete_account(key)
        om.add_account(saved)
        return {"five_hour": {"utilization": 100}}
    monkeypatch.setattr(om, "fetch_usage_snapshot", fetch)
    assert await om.ensure_quota_fresh(key) is False
    assert state_db.quota_load(key) is None
    assert om.get_account(key)["enabled"] is True


@pytest.mark.parametrize("provider", ["claude", "openai"])
def test_late_http_headers_cannot_disable_replacement(clean_accounts, provider):
    key, old = add(entry_for(provider))
    saved = copy.deepcopy(om.get_account(key))
    om.delete_account(key); om.add_account(saved)
    response = SimpleNamespace(headers={
        "x-codex-primary-used-percent": "100", "x-codex-primary-reset-after-seconds": "3600",
        "anthropic-ratelimit-unified-5h-utilization": "1.0",
        "anthropic-ratelimit-unified-5h-surpassed-threshold": "true",
    })
    failover._maybe_record_codex_snapshot(old, response)
    failover._maybe_record_anthropic_snapshot(old, response)
    assert state_db.quota_load(key) is None
    assert om.get_account(key)["enabled"] is True
    assert not om.get_account(key).get("disabled_reason")

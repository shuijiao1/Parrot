"""Atomic candidate-publication regressions for OAuth management batches."""
from __future__ import annotations

import copy
import json
import os

import pytest

from src.tests import _isolation

_isolation.isolate()

from src import config, oauth_manager  # noqa: E402
from src.management_control.oauth import OAuthBackend  # noqa: E402


def _openai_account(email: str, workspace: str, access: str, *, models=None) -> dict:
    return {
        "email": email,
        "provider": "openai",
        "type": "openai",
        "workspace_id": workspace,
        "chatgpt_account_id": workspace,
        "access_token": access,
        "refresh_token": f"refresh-{access}",
        "enabled": True,
        "models": list(models or []),
    }


def _claude_invalid(email: str) -> dict:
    return {
        "email": email,
        "provider": "claude",
        "type": "claude",
        "access_token": f"access-{email}",
        "refresh_token": f"refresh-{email}",
        "enabled": False,
        "disabled_reason": "auth_error",
        "models": ["claude-test"],
    }


def _private_config(tmp_path, monkeypatch, accounts: list[dict]):
    path = tmp_path / "config.json"
    initial = copy.deepcopy(config.DEFAULT_CONFIG)
    initial["oauthAccounts"] = copy.deepcopy(accounts)
    channels = [f"oauth:{oauth_manager.get_account_key(item)}" for item in accounts]
    initial["loadBalancing"] = {
        "initialized": True,
        "channelPriorityOrder": list(channels),
        "priorityOrders": {
            "anthropic": list(channels),
            "openai": list(channels),
        },
        "modelPriorityOrders": {
            "shared-model": list(channels),
            "removed-only": list(channels[:2]),
        },
    }
    path.write_text(json.dumps(initial, ensure_ascii=False, indent=2), encoding="utf-8")

    monkeypatch.setattr(config, "CONFIG_PATH", str(path))
    monkeypatch.setattr(config, "_cache", copy.deepcopy(initial))
    monkeypatch.setattr(config, "_mtime", os.path.getmtime(path))
    monkeypatch.setattr(config, "_reload_callbacks", [])

    writes: list[dict] = []
    callbacks: list[dict] = []
    original_write = config._write_atomic

    def record_write(candidate: dict) -> None:
        writes.append(copy.deepcopy(candidate))
        original_write(candidate)

    monkeypatch.setattr(config, "_write_atomic", record_write)
    config.on_reload(lambda candidate: callbacks.append(copy.deepcopy(candidate)))
    return path, copy.deepcopy(initial), writes, callbacks


def _candidate(candidate_id: str, entry: dict) -> dict:
    return {"candidate_id": candidate_id, "entry": copy.deepcopy(entry)}


@pytest.mark.parametrize("first_action", ["add", "replace"])
def test_import_second_item_failure_discards_first_candidate_change(
    tmp_path, monkeypatch, first_action,
):
    existing = _openai_account(
        "existing@example.test", "workspace-existing", "old-access", models=["kept-model"],
    )
    initial_accounts = [existing]
    path, before, writes, callbacks = _private_config(
        tmp_path, monkeypatch, initial_accounts,
    )
    if first_action == "replace":
        first = _openai_account(
            "existing@example.test", "workspace-existing", "new-access", models=["ignored-new"],
        )
    else:
        first = _openai_account(
            "first-add@example.test", "workspace-first", "first-access",
        )
    second = _openai_account(
        "second-add@example.test", "workspace-second", "second-access",
    )
    candidates = (
        _candidate("candidate-1", first),
        _candidate("candidate-2", second),
    )
    choices = {"candidate-1": "overwrite", "candidate-2": "overwrite"}

    original_apply = oauth_manager._apply_import_candidate_to_config
    applied: list[str] = []

    def fail_second(candidate_config, item, choice):
        applied.append(item["candidate_id"])
        if len(applied) == 2:
            raise RuntimeError("injected second import apply failure")
        return original_apply(candidate_config, item, choice)

    monkeypatch.setattr(oauth_manager, "_apply_import_candidate_to_config", fail_second)
    held_cache = config._cache
    with pytest.raises(RuntimeError, match="second import apply failure"):
        OAuthBackend().commit_import_conditional(
            copy.deepcopy(initial_accounts), candidates, choices,
        )

    assert applied == ["candidate-1", "candidate-2"]
    assert config._cache is held_cache
    assert config.get() == before
    assert json.loads(path.read_text(encoding="utf-8")) == before
    assert writes == []
    assert callbacks == []
    current = config.get()["oauthAccounts"]
    if first_action == "replace":
        assert current[0]["access_token"] == "old-access"
        assert current[0]["models"] == ["kept-model"]
    else:
        assert all(item["email"] != "first-add@example.test" for item in current)


def test_import_success_publishes_add_replace_and_lb_once(tmp_path, monkeypatch):
    existing = _openai_account(
        "existing@example.test", "workspace-existing", "old-access", models=["kept-model"],
    )
    path, before, writes, callbacks = _private_config(tmp_path, monkeypatch, [existing])
    replacement = _openai_account(
        "existing@example.test", "workspace-existing", "new-access", models=["new-model"],
    )
    added = _openai_account(
        "added@example.test", "workspace-added", "added-access", models=["added-model"],
    )
    candidates = (
        _candidate("candidate-1", replacement),
        _candidate("candidate-2", added),
    )

    outcome = OAuthBackend().commit_import_conditional(
        copy.deepcopy(before["oauthAccounts"]),
        candidates,
        {"candidate-1": "overwrite", "candidate-2": "overwrite"},
    )

    existing_id = oauth_manager.get_account_key(existing)
    added_id = oauth_manager.get_account_key(added)
    assert outcome == {
        "status": "committed",
        "added": [added_id],
        "replaced": [existing_id],
        "skipped": [],
    }
    assert len(writes) == 1
    assert len(callbacks) == 1
    assert callbacks[0] == writes[0] == config.get()
    assert json.loads(path.read_text(encoding="utf-8")) == config.get()
    current = {oauth_manager.get_account_key(item): item for item in config.get()["oauthAccounts"]}
    assert current[existing_id]["access_token"] == "new-access"
    assert current[existing_id]["models"] == ["kept-model"]
    assert current[added_id]["access_token"] == "added-access"
    assert current[added_id]["provider"] == "openai"
    added_channel = f"oauth:{added_id}"
    assert config.get()["loadBalancing"]["channelPriorityOrder"][-1] == added_channel
    assert config.get()["loadBalancing"]["priorityOrders"]["openai"][-1] == added_channel


def _patch_delete_runtime(monkeypatch):
    from src import affinity, channel_state, concurrency, cooldown, failover, scorer, state_db

    events = {
        "retire_deleted": [],
        "restore_deleted": [],
        "retire_channel": [],
        "scorer": [],
        "cooldown": [],
        "server_affinity": [],
        "client_affinity": [],
        "quota": [],
        "codex": [],
        "anthropic": [],
        "probe": [],
    }
    monkeypatch.setattr(channel_state, "alias_sources", lambda _channel: set())
    monkeypatch.setattr(
        channel_state, "retire_deleted", lambda channel: events["retire_deleted"].append(channel),
    )
    monkeypatch.setattr(
        channel_state, "restore_deleted", lambda channel: events["restore_deleted"].append(channel),
    )
    monkeypatch.setattr(concurrency, "capture_rename_limit", lambda _channel: 7)
    monkeypatch.setattr(
        concurrency,
        "retire_channel",
        lambda channel, **kwargs: events["retire_channel"].append((channel, kwargs)),
    )
    monkeypatch.setattr(scorer, "clear_stats", lambda channel: events["scorer"].append(channel))
    monkeypatch.setattr(
        cooldown,
        "clear",
        lambda channel, **_kwargs: events["cooldown"].append(channel),
    )
    monkeypatch.setattr(
        affinity, "delete_by_channel", lambda channel: events["server_affinity"].append(channel),
    )
    monkeypatch.setattr(
        affinity, "client_delete_by_channel", lambda channel: events["client_affinity"].append(channel),
    )
    monkeypatch.setattr(state_db, "quota_delete", lambda account: events["quota"].append(account))
    monkeypatch.setattr(
        failover, "forget_codex_snapshot", lambda account: events["codex"].append(account),
    )
    monkeypatch.setattr(
        failover,
        "forget_anthropic_snapshot",
        lambda account: events["anthropic"].append(account),
    )
    monkeypatch.setattr(
        oauth_manager, "forget_openai_probe", lambda account: events["probe"].append(account),
    )
    return events


def test_invalid_delete_second_apply_failure_keeps_accounts_and_lb_unpublished(
    tmp_path, monkeypatch,
):
    first = _claude_invalid("invalid-one@example.test")
    second = _claude_invalid("invalid-two@example.test")
    path, before, writes, callbacks = _private_config(tmp_path, monkeypatch, [first, second])
    events = _patch_delete_runtime(monkeypatch)
    expected = tuple(
        (oauth_manager.get_account_key(item), copy.deepcopy(item))
        for item in (first, second)
    )
    original_remove = oauth_manager._remove_exact_account_from_config
    removed: list[str] = []

    def fail_second(candidate_config, account_key):
        removed.append(account_key)
        if len(removed) == 2:
            raise RuntimeError("injected second delete apply failure")
        original_remove(candidate_config, account_key)

    monkeypatch.setattr(oauth_manager, "_remove_exact_account_from_config", fail_second)
    with pytest.raises(RuntimeError, match="second delete apply failure"):
        OAuthBackend().delete_invalid_accounts_conditional(expected)

    assert removed == [item[0] for item in expected]
    assert config.get() == before
    assert json.loads(path.read_text(encoding="utf-8")) == before
    assert writes == []
    assert callbacks == []
    channels = {f"oauth:{item[0]}" for item in expected}
    assert set(events["retire_deleted"]) == channels
    assert set(events["restore_deleted"]) == channels
    assert events["retire_channel"] == []
    assert events["scorer"] == []


def test_invalid_delete_second_snapshot_change_keeps_first_and_lb(
    tmp_path, monkeypatch,
):
    first = _claude_invalid("invalid-one@example.test")
    second = _claude_invalid("invalid-two@example.test")
    path, before, writes, callbacks = _private_config(tmp_path, monkeypatch, [first, second])
    _patch_delete_runtime(monkeypatch)
    stale_second = copy.deepcopy(second)
    stale_second["concurrent"] = "changed-after-plan"
    expected = (
        (oauth_manager.get_account_key(first), copy.deepcopy(first)),
        (oauth_manager.get_account_key(second), stale_second),
    )

    outcome = OAuthBackend().delete_invalid_accounts_conditional(expected)

    assert outcome == {"status": "revision_conflict"}
    assert config.get() == before
    assert json.loads(path.read_text(encoding="utf-8")) == before
    assert writes == []
    assert callbacks == []


def test_invalid_delete_success_publishes_config_lb_once_then_cleans_runtime(
    tmp_path, monkeypatch,
):
    first = _claude_invalid("invalid-one@example.test")
    second = _claude_invalid("invalid-two@example.test")
    survivor = _openai_account("survivor@example.test", "survivor-workspace", "survivor-access")
    path, _before, writes, callbacks = _private_config(
        tmp_path, monkeypatch, [first, second, survivor],
    )
    events = _patch_delete_runtime(monkeypatch)
    expected = tuple(
        (oauth_manager.get_account_key(item), copy.deepcopy(item))
        for item in (first, second)
    )

    outcome = OAuthBackend().delete_invalid_accounts_conditional(expected)

    assert outcome == {"status": "deleted", "count": 2}
    assert len(writes) == 1
    assert len(callbacks) == 1
    assert callbacks[0] == writes[0] == config.get()
    assert json.loads(path.read_text(encoding="utf-8")) == config.get()
    survivor_id = oauth_manager.get_account_key(survivor)
    assert [oauth_manager.get_account_key(item) for item in config.get()["oauthAccounts"]] == [
        survivor_id,
    ]
    survivor_channel = f"oauth:{survivor_id}"
    lb = config.get()["loadBalancing"]
    assert lb["channelPriorityOrder"] == [survivor_channel]
    assert lb["priorityOrders"]["anthropic"] == [survivor_channel]
    assert lb["priorityOrders"]["openai"] == [survivor_channel]
    assert lb["modelPriorityOrders"]["shared-model"] == [survivor_channel]
    assert "removed-only" not in lb["modelPriorityOrders"]

    account_ids = {item[0] for item in expected}
    channels = {f"oauth:{account_id}" for account_id in account_ids}
    assert set(events["retire_deleted"]) == channels
    assert events["restore_deleted"] == []
    assert {item[0] for item in events["retire_channel"]} == channels
    assert set(events["scorer"]) == channels
    assert set(events["cooldown"]) == channels
    assert set(events["server_affinity"]) == channels
    assert set(events["client_affinity"]) == channels
    for key in ("quota", "codex", "anthropic", "probe"):
        assert set(events[key]) == account_ids

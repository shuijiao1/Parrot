"""Keep production Codex owner cleanup on management's atomic batch path."""
from __future__ import annotations

import copy

import pytest

from src import config, oauth_manager, state_db
from src.openai import reasoning_replay
from src.openai.codex_identity import owner_digest_for_workspace
from src.state_store import StateStore
from src.tests.test_oauth_batch_atomic import _patch_delete_runtime, _private_config


@pytest.mark.parametrize("outcome", ["success", "revision_conflict", "write_failure"])
def test_batch_delete_cleans_codex_owners_only_after_config_publication(
    tmp_path, monkeypatch, outcome,
):
    workspace = "sync-batch-workspace"
    owner = owner_digest_for_workspace(workspace)
    installation = "11111111-1111-4111-8111-111111111111"
    identity = {
        "schemaVersion": 1,
        "idGenerationVersion": 1,
        "protocolProfile": "rust-v0.153.4",
        "ownerKind": "chatgpt-account-id",
        "ownerDigest": owner,
        "installationId": installation,
        "createdAt": "2026-09-05T00:00:00Z",
    }
    account = {
        "email": "sync-batch@example.test",
        "provider": "openai",
        "type": "openai",
        "workspace_id": workspace,
        "chatgpt_account_id": workspace,
        "access_token": "fake-access",
        "refresh_token": "fake-refresh",
        "enabled": False,
        "disabled_reason": "auth_error",
        "models": ["gpt-6-astra"],
        "codexIdentity": identity,
        "codexDeviceInstallationId": installation,
    }
    account_key = oauth_manager.get_account_key(account)
    path, before, writes, callbacks = _private_config(tmp_path, monkeypatch, [account])
    initial_disk = path.read_bytes()
    _patch_delete_runtime(monkeypatch)
    store = StateStore(
        str(tmp_path / "runtime.json"), str(tmp_path / "durable.json"),
        manifest_path=str(tmp_path / "manifest.json"),
    )
    store.start()
    monkeypatch.setattr(state_db, "_store", store)
    principal = "sha256:" + "2" * 64
    anchor = "sha256:" + "3" * 64
    other_owner = "sha256:" + "4" * 64
    cleanup_events = []

    def cleanup_replay(owner_digest):
        # Cleanup must see the successfully published configuration, not a
        # candidate with a still-live account or a failed persistence attempt.
        assert config.get()["oauthAccounts"] == []
        assert len(writes) == len(callbacks) == 1
        cleanup_events.append(owner_digest)

    monkeypatch.setattr(reasoning_replay, "delete_owner", cleanup_replay)
    try:
        for digest, install in (
            (owner, installation),
            (other_owner, "22222222-2222-4222-8222-222222222222"),
        ):
            state_db.codex_identity_tombstone_claim(
                digest, install, 1, created_at=identity["createdAt"],
            )
            state_db.codex_logical_session_resolve({
                "owner_digest": digest,
                "downstream_principal_digest": principal,
                "downstream_anchor_digest": anchor,
                "session_id": "session-" + digest,
                "window_number": 0,
            })
            state_db.compaction_owner_upsert(
                "compaction-" + digest, "digest", account_key, digest,
                model="gpt-6-astra", logical_session_id="session-" + digest,
            )
        expected = copy.deepcopy(account)
        if outcome == "revision_conflict":
            expected["access_token"] = "stale-access"
        if outcome == "write_failure":
            def fail_write(_candidate):
                raise OSError("injected config write failure")
            monkeypatch.setattr(config, "_write_atomic", fail_write)
            with pytest.raises(OSError, match="injected config write failure"):
                oauth_manager.delete_invalid_accounts_batch_if_unchanged(((account_key, expected),))
        else:
            result = oauth_manager.delete_invalid_accounts_batch_if_unchanged(((account_key, expected),))
            assert result["status"] == ("deleted" if outcome == "success" else outcome)

        assert state_db.codex_identity_tombstone_load(owner)["installation_id"] == installation
        assert state_db.codex_identity_tombstone_load(other_owner) is not None
        assert state_db.codex_logical_session_load(other_owner, principal, anchor) is not None
        assert state_db.compaction_owner_load("compaction-" + other_owner, "digest") is not None
        if outcome == "success":
            assert config.get()["oauthAccounts"] == []
            assert state_db.codex_logical_session_load(owner, principal, anchor) is None
            assert state_db.compaction_owner_load("compaction-" + owner, "digest") is None
            assert cleanup_events == [owner]
            assert len(writes) == len(callbacks) == 1
        else:
            assert config.get() == before
            assert path.read_bytes() == initial_disk
            assert state_db.codex_logical_session_load(owner, principal, anchor) is not None
            assert state_db.compaction_owner_load("compaction-" + owner, "digest") is not None
            assert cleanup_events == []
            assert writes == callbacks == []
    finally:
        store.close()

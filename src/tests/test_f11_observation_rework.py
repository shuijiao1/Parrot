from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from src import config, state_db
from src.management_control.composition import ObservabilityControls
from src.management_control.observability import StatusControl
from src.oauth_ids import account_key
from src.tests.management_observability_support import build_client, fake_controls
from src.tests.test_s11_observability_contract import Authority, _real_controls


class _Config:
    def __init__(self, value):
        self.value = value

    def get(self):
        return copy.deepcopy(self.value)


class _OAuth:
    OAUTH_MODEL_SYNC_CHECK_INTERVAL_SECONDS = 60

    def __init__(self, cfg):
        self.cfg = cfg

    def list_accounts(self):
        return copy.deepcopy(self.cfg["oauthAccounts"])

    @staticmethod
    def get_account_key(value):
        return account_key(value)

    @staticmethod
    def provider_of(value):
        return str(value.get("provider") or "claude")

    @staticmethod
    def fable_display_from_quota_row(_row):
        return None, None


class _LogDb:
    @staticmethod
    def stats_summary(**_kwargs):
        return {"overall": {}}

    @staticmethod
    def stats_lifetime():
        return {"overall": {}}


class _Registry:
    @staticmethod
    def all_channels():
        return []


class _Cooldown:
    @staticmethod
    def active_entries():
        return []


class _Scorer:
    @staticmethod
    def snapshot():
        return []


class _Affinity:
    count = staticmethod(lambda: 0)
    client_count = staticmethod(lambda: 0)


class _Limiter:
    totals = staticmethod(lambda: {})
    snapshot = staticmethod(lambda: [])


class _QuotaErrors:
    active_quota_cooldown = staticmethod(lambda _row: False)


def _status(cfg):
    return StatusControl(
        config=_Config(cfg), registry=_Registry(), cooldown=_Cooldown(),
        scorer=_Scorer(), affinity=_Affinity(), concurrency=_Limiter(),
        apikey_limiter=_Limiter(), log_db=_LogDb(), oauth_manager=_OAuth(cfg),
        quota_errors=_QuotaErrors(), state_db=state_db,
        status_monitor=SimpleNamespace(snapshot_active=lambda: {}),
        now=lambda: 1_800_000_000.0, service_started_at=1_799_999_900.0,
    )


def _get(client, auth, path):
    response = client.get("/api/management/v1" + path, headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_management_quota_views_require_exact_canonical_state_rows(tmp_path, monkeypatch):
    claude = {"provider": "claude", "email": "current@example.invalid"}
    openai = {
        "provider": "openai", "email": "shared@example.invalid",
        "workspace_id": "workspace-current",
    }
    cfg = {
        "stateDbPath": str(tmp_path / "absent-state.db"),
        "runtimeStatePath": "runtime.json", "durableStatePath": "durable.json",
        "oauthAccounts": [claude, openai],
        "listen": {"host": "127.0.0.1", "port": 22123}, "apiKeys": {},
    }
    state_db.close()
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config, "get", lambda: copy.deepcopy(cfg))
    state_db.init()

    claude_key = account_key(claude)
    openai_key = account_key(openai)
    other_workspace_key = account_key({
        **openai, "workspace_id": "workspace-deleted",
    })
    state_db.quota_save(
        "deleted-account-row", {"fetched_at": 1, "seven_day_util": 99},
        email=claude["email"],
    )
    state_db.quota_save(
        other_workspace_key, {"fetched_at": 1, "seven_day_util": 98},
        email=openai["email"],
    )
    # Preserve and directly prove the legacy lookup behavior that Management
    # must not use: the unique email fallback resolves the Claude orphan.
    assert state_db.quota_load(claude_key)["account_key"] == "deleted-account-row"
    assert other_workspace_key != openai_key

    controls = fake_controls()
    controls.status = _status(cfg)
    client, runtime, _, auth = build_client(
        tmp_path / "management", controls_value=controls,
    )
    try:
        rows_before = state_db.quota_load_all()
        overview = _get(client, auth, "/overview")["data"]
        status = _get(client, auth, "/runtime/status")["data"]
        assert overview["counts"]["quotaHot"] == 0
        assert status["quotaWarnings"] == []
        assert _get(client, auth, "/overview")["data"]["revision"] == overview["revision"]
        assert _get(client, auth, "/runtime/status")["data"]["revision"] == status["revision"]
        assert state_db.quota_load_all() == rows_before

        state_db.quota_save(
            claude_key, {"fetched_at": 2, "seven_day_util": 97},
            email=claude["email"],
        )
        state_db.quota_save(
            openai_key, {"fetched_at": 2, "seven_day_util": 96},
            email=openai["email"],
        )
        overview_with_exact = _get(client, auth, "/overview")["data"]
        status_with_exact = _get(client, auth, "/runtime/status")["data"]
        assert overview_with_exact["counts"]["quotaHot"] == 2
        assert {
            row["accountId"] for row in status_with_exact["quotaWarnings"]
        } == {claude_key, openai_key}
        assert overview_with_exact["revision"] != overview["revision"]
        assert status_with_exact["revision"] != status["revision"]
    finally:
        client.close()
        runtime.close()
        state_db.close()


def test_runtime_apis_hide_free_form_cooldown_error_and_keep_diagnostics(tmp_path):
    artifact = tmp_path / "artifact.png"
    artifact.write_bytes(b"artifact")
    authority = Authority(artifact)
    secret = authority.config_data["channels"][0]["apiKey"]
    raw_error = f'HTTP 401: {{"api_key":"{secret}"}}'
    authority.cooldown_rows[0]["last_error_message"] = raw_error
    controls: ObservabilityControls = _real_controls(authority)
    client, runtime, _, auth = build_client(tmp_path, controls_value=controls)
    try:
        runtime_payload = _get(client, auth, "/runtime/status")
        cooldown_payload = _get(client, auth, "/runtime/cooldowns")
        emitted = json.dumps({
            "runtime": runtime_payload, "cooldowns": cooldown_payload,
        })
        assert secret not in emitted
        assert raw_error not in emitted

        channel = runtime_payload["data"]["channels"][0]
        assert channel["health"] == "cooldown"
        assert channel["cooldownCount"] == 1
        assert channel["cooldowns"][0] == {
            "model": "model-one", "errorCount": 2, "state": "active",
            "until": "2030-03-17T17:46:40Z", "quota": False, "message": None,
        }
        assert channel["problemReasons"] == ["active"]
        cooldown = cooldown_payload["data"][0]
        assert cooldown["errorCount"] == 2
        assert cooldown["state"] == "active"
        assert cooldown["message"] is None

        runtime_revision = runtime_payload["data"]["revision"]
        cooldown_item_revision = cooldown["revision"]
        cooldown_page_revision = cooldown_payload["meta"]["revision"]
        authority.cooldown_rows[0]["last_error_message"] = (
            'HTTP 403: {"api_key":"another-hidden-secret"}'
        )
        assert _get(client, auth, "/runtime/status")["data"]["revision"] == runtime_revision
        cooldown_again = _get(client, auth, "/runtime/cooldowns")
        assert cooldown_again["data"][0]["revision"] == cooldown_item_revision
        assert cooldown_again["meta"]["revision"] == cooldown_page_revision
        assert authority.mutation_calls == []
    finally:
        client.close()
        runtime.close()

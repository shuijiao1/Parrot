"""Cross-package wiring contracts, with real runtime owners and SQLite history."""
from __future__ import annotations

from datetime import timedelta

from src import log_db
from src.management_control.apikey import ApiKeyProvenance, ApiKeySource
from src.management_control.observability import LogsControl, StatsControl
from src.tests.management_observability_support import build_client, fake_controls
from src.tests.test_management_apikey_control import FakeConfig, FakeLimiter, FakeModels, FakeStats
from src.tests.test_management_apikey_provenance_s6 import read_context, telegram_context
from src.tests.test_management_logs import FakeLogDb
from src.tests.test_s4_management_logs_cross_month import (
    _create_month, monthly_log_store,
)


def test_runtime_owner_injects_its_store_for_tg_key_provenance(tmp_path):
    client, runtime, _, _ = build_client(tmp_path, inject_controls=False)
    try:
        control = runtime.control_owner().api_keys
        assert control._provenance_store is runtime.state_store
        control._config = FakeConfig({"apiKeys": {}})
        control._limiter = FakeLimiter()
        control._models = FakeModels()
        control._stats = FakeStats()
        result = control.create_api_key(
            telegram_context(), name="tg-integrated", mode=ApiKeySource.CUSTOM,
            custom_secret="integration-custom-key",
        )
        assert control.get_api_key(read_context(), "tg-integrated").source is ApiKeyProvenance.CUSTOM
        assert "source" not in control._config.get()["apiKeys"]["tg-integrated"]
        assert result is not None
    finally:
        client.close()
        runtime.close()


def test_log_body_revision_wiring_uses_same_snapshot_for_list_and_item(tmp_path):
    database = FakeLogDb()
    controls = fake_controls()
    controls.logs = LogsControl(log_db=database)
    client, runtime, _, auth = build_client(tmp_path, controls_value=controls)
    base = "/api/management/v1/logs/r2"
    try:
        response = client.get(base + "/body?kind=request&pageSize=1", headers=auth)
        assert response.status_code == 200, response.text
        first = response.json()
        item = first["data"][0]
        detail = client.get(base + f"/body/items/{item['id']}?kind=request", headers=auth)
        assert detail.status_code == 200, detail.text
        assert item["revision"] == detail.json()["data"]["revision"]
        other_page = client.get(base + "/body?kind=request&page=2&pageSize=1", headers=auth)
        assert other_page.json()["meta"]["revision"] == first["meta"]["revision"]
        raw = client.get(base + "/raw-body?kind=request", headers=auth)
        assert raw.status_code == 200, raw.text
        before = raw.json()["data"]
        assert before["body"]["api_key"] == "secret"
        assert before["revision"]
        repeated = client.get(base + "/raw-body?kind=request", headers=auth).json()["data"]
        assert repeated == before
        database.rows[1]["status"] = "error"
        changed = client.get(base + "/raw-body?kind=request", headers=auth).json()["data"]
        assert changed["revision"] != before["revision"]
        assert changed["body"] == before["body"]
    finally:
        client.close()
        runtime.close()


def test_stats_recent_calls_uses_management_history_without_changing_tg(monthly_log_store, tmp_path):
    month = monthly_log_store["older"]
    _create_month(monthly_log_store, month, [{
        "id": "historic-recent-call", "created_at": (month + timedelta(days=3)).timestamp(),
    }])
    assert log_db.recent_logs_count() == 0
    controls = fake_controls()
    controls.stats = StatsControl(log_db=log_db)
    client, runtime, _, auth = build_client(tmp_path, controls_value=controls)
    try:
        response = client.get("/api/management/v1/stats/recent-calls", headers=auth)
        assert response.status_code == 200, response.text
        value = response.json()
        assert value["meta"]["total"] == 1
        assert value["data"][0]["id"] == "historic-recent-call"
        assert log_db.recent_logs_count() == 0
    finally:
        client.close()
        runtime.close()

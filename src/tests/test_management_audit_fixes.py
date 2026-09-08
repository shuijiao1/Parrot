"""Regression cases for the seven bounded 2026-09-06 delivery-audit fixes."""
from __future__ import annotations

import copy
import time
from urllib.parse import quote

import httpx
import pytest

from src import config, log_db, state_db, status_monitor, update_checker, updater
from src.management_auth.principal import AuthMethod, ManagementPrincipal
from src.management_control import ManagementContext
from src.telegram import states
from src.telegram.menus import channel_menu
from src.tests.test_management_delivery_regressions import PREFIX, actual_management


def _channel(name: str = "audit-channel") -> dict:
    return {
        "mode": "manual", "name": name, "baseUrl": "https://example.test",
        "apiKey": "audit-channel-key", "protocol": "anthropic",
        "models": [{"real": "provider/model", "alias": "provider/model"}],
    }


def test_one_time_key_response_fields_are_not_write_only(actual_management):
    client, _runtime = actual_management
    schemas = client.app.openapi()["components"]["schemas"]
    for schema, field in (("ApiKeySecretData", "secret"), ("ApiKeyReplacementPlanData", "planToken")):
        assert not schemas[schema]["properties"][field].get("writeOnly", False)
    for schema, field in (("ApiKeyCreateRequest", "customSecret"),
                          ("ApiKeyReplaceSecretRequest", "customSecret"),
                          ("ApiKeyRegenerateRequest", "planToken")):
        assert schemas[schema]["properties"][field]["writeOnly"] is True


@pytest.mark.parametrize("bad_url", ["not-a-url", "ftp://example.test"])
def test_channel_url_rejected_before_write_or_operation(actual_management, bad_url):
    client, _runtime = actual_management
    created = client.post(PREFIX + "/channels", json=_channel())
    assert created.status_code == 201, created.text
    channel_id = created.json()["data"]["id"]
    before = copy.deepcopy(config.get())
    create_body = {**_channel("invalid-channel"), "baseUrl": bad_url}
    requests = (
        client.post(PREFIX + "/channels", json=create_body),
        client.patch(PREFIX + "/channels/" + quote(channel_id, safe=""), json={"baseUrl": bad_url}),
        client.post(PREFIX + "/channel-model-discoveries", json={
            "source": "draft", "baseUrl": bad_url, "apiKey": "audit-channel-key", "protocol": "anthropic",
        }),
        client.post(PREFIX + "/channel-drafts/probes", json={
            "name": "bad-draft", "baseUrl": bad_url, "apiKey": "audit-channel-key",
            "protocol": "anthropic", "model": "provider/model",
        }),
    )
    for response in requests:
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
    assert config.get() == before


def test_existing_channel_rename_keeps_original_long_name_semantics(actual_management, monkeypatch):
    client, _runtime = actual_management
    assert client.post(PREFIX + "/channels", json=_channel("short")).status_code == 201
    short = channel_menu.ui.register_code("short")
    states.set_state(42, "ch_edit_name", {"short": short})
    sent: list[str] = []
    monkeypatch.setattr(channel_menu.ui, "send", lambda _chat, text, **_kwargs: sent.append(text))
    monkeypatch.setattr(channel_menu.ui, "send_result", lambda *_args, **_kwargs: None)
    name = "N" * 65
    assert channel_menu.handle_edit_text(42, "ch_edit_name", name) is True
    assert any(row.get("name") == name for row in config.get()["channels"]), sent
    path = PREFIX + "/channels/" + quote("api:" + name, safe="")
    assert client.get(path).json()["data"]["name"] == name
    renamed = client.patch(path, json={"name": "M" * 65})
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["data"]["name"] == "M" * 65
    # The original new-channel limit is a different rule and stays intact.
    denied_create = client.post(PREFIX + "/channels", json=_channel("C" * 65))
    assert denied_create.status_code == 422


@pytest.mark.parametrize("kind", ["request", "response"])
def test_log_body_query_uses_existing_public_item_contract(actual_management, kind):
    client, _runtime = actual_management
    config.update(lambda root: root.update({"logStoreBodies": True}))
    log_id = "audit-body-query-" + kind
    request_body = {"messages": [{"role": "user", "content": "needle-body-中文"}]}
    response_body = '{"type":"message","content":[{"type":"text","text":"needle-body-中文"}]}'
    handle = log_db.insert_pending(log_id, "127.0.0.1", "audit", "provider/model", False, 1, 0, {}, request_body)
    log_db.finish_success(handle, "api:audit", "api", "provider/model", response_body=response_body)
    path = PREFIX + "/logs/" + log_id + "/body"
    plain = client.get(path, params={"kind": kind})
    assert plain.status_code == 200, plain.text
    public_fields = set(plain.json()["data"][0])
    for sort in ("original", "reverse", "size", "type"):
        found = client.get(path, params={"kind": kind, "query": "needle-body", "sort": sort, "pageSize": 1})
        assert found.status_code == 200, found.text
        assert found.json()["meta"]["total"] >= 1
        assert len(found.json()["data"]) == 1
        item = found.json()["data"][0]
        assert "needle-body-中文" in item["text"]
        assert set(item) == public_fields
        assert "matchCount" not in item
        single = client.get(path + "/items/" + item["id"], params={"kind": kind})
        assert single.status_code == 200, single.text
        assert single.json()["data"] == item
    missing = client.get(path, params={"kind": kind, "query": "not-present-in-this-body"})
    assert missing.status_code == 200 and missing.json()["data"] == []
    assert missing.json()["meta"]["total"] == 0


def _telegram_context() -> ManagementContext:
    return ManagementContext(
        request_id="audit-tg-compatibility",
        actor=ManagementPrincipal.administrator(subject_id="42", auth_method=AuthMethod.TELEGRAM_ADMIN),
    )


def _terminal(client, operation_id: str) -> dict:
    for _ in range(100):
        response = client.get(PREFIX + "/operations/" + operation_id)
        assert response.status_code == 200, response.text
        operation = response.json()["data"]
        if operation["status"] in {"succeeded", "failed", "cancelled", "interrupted"}:
            return operation
        time.sleep(0.01)
    pytest.fail("bounded management operation did not finish")


def test_update_api_only_checks_while_telegram_keeps_auto_stage(actual_management, monkeypatch):
    client, runtime = actual_management
    repo = "audit/pure-update-check"
    config.update(lambda root: root.update({"updateChecker": {
        "enabled": True, "autoUpdate": True, "includePrerelease": False,
        "repo": repo, "apiBase": "https://releases.example.test", "ignoredVersions": [],
    }}))
    monkeypatch.setattr(update_checker, "_latest_cache", None)
    stage_calls, notifications, http_calls = [], [], []
    release = {
        "tag_name": "v999.3.0", "name": "Release", "body": "changes",
        "html_url": "https://releases.example.test/v999.3.0", "draft": False, "prerelease": False,
    }

    def fetch(url, *, timeout, headers):
        http_calls.append(url)
        return httpx.Response(200, json=[release], request=httpx.Request("GET", url))

    def stage(version, *, chat_id=None, notify_msg_id=None):
        stage_calls.append(version)
        return True, "staged"

    monkeypatch.setattr(update_checker.network, "get_sync", fetch)
    monkeypatch.setattr(updater, "is_busy", lambda: False)
    monkeypatch.setattr(updater, "stage_update", stage)
    monkeypatch.setattr(update_checker.notifier, "notify_event", lambda *a, **kw: notifications.append((a, kw)))
    before = updater.load_state()
    checked = client.post(PREFIX + "/updates/actions/check")
    assert checked.status_code == 200, checked.text
    assert checked.json()["data"]["candidateVersion"] == "v999.3.0"
    assert checked.json()["data"]["changelog"] == "changes"
    assert stage_calls == [] and notifications == []
    assert updater.load_state() == before
    assert state_db.update_state_load(repo)["notified_for"] is None

    runtime.control_owner().auxiliary.updates.refresh_direct(_telegram_context())
    assert stage_calls == ["v999.3.0"] and len(notifications) == 1
    assert state_db.update_state_load(repo)["notified_for"] == "v999.3.0"
    assert http_calls == ["https://releases.example.test/repos/audit/pure-update-check/releases?per_page=20"] * 2


@pytest.mark.parametrize("warm_cache", [False, True])
def test_update_api_reports_fetch_failure_without_changing_tg_fallback(actual_management, monkeypatch, warm_cache):
    client, runtime = actual_management
    config.update(lambda root: root.update({"updateChecker": {
        "enabled": True, "autoUpdate": False, "repo": "audit/update-failure", "ignoredVersions": [],
    }}))
    previous = {"latest_version": "v999.0.0", "latest_name": "old release"} if warm_cache else None
    monkeypatch.setattr(update_checker, "_latest_cache", copy.deepcopy(previous))

    def unavailable(url, *, timeout, headers):
        raise RuntimeError("synthetic release network failure")

    monkeypatch.setattr(update_checker.network, "get_sync", unavailable)
    checked = client.post(PREFIX + "/updates/actions/check")
    assert checked.status_code == 502, checked.text
    assert checked.json()["error"]["code"] == "UPSTREAM_ERROR"
    assert update_checker.get_cached() == previous
    runtime.control_owner().auxiliary.updates.refresh_direct(_telegram_context())
    assert update_checker.get_cached() == previous

    # A successful empty feed must remain distinguishable from a failed fetch.
    def empty_feed(url, *, timeout, headers):
        return httpx.Response(200, json=[], request=httpx.Request("GET", url))

    monkeypatch.setattr(update_checker.network, "get_sync", empty_feed)
    checked_empty = client.post(PREFIX + "/updates/actions/check")
    assert checked_empty.status_code == 200, checked_empty.text
    assert checked_empty.json()["data"]["candidateVersion"] is None


@pytest.mark.parametrize("partial_success", [False, True])
def test_status_api_reports_failure_and_preserves_tg_fallback(actual_management, monkeypatch, partial_success):
    client, runtime = actual_management
    targets = ["claude", "openai"] if partial_success else ["openai"]
    config.update(lambda root: root.update({"statusMonitor": {
        "enabled": True, "targets": targets, "intervalSeconds": 300, "minImpact": "none",
    }}))
    previous_active = {"audit-status-existing": {"id": "audit-status-existing", "name": "Existing", "impact": "major"}}
    monkeypatch.setattr(status_monitor, "_initialized_providers", set())
    monkeypatch.setattr(status_monitor, "_active", {"claude": {}, "openai": copy.deepcopy(previous_active), "cloudflare": {}})
    monkeypatch.setattr(status_monitor.notifier, "notify_event", lambda *a, **kw: None)

    def unavailable(url, *, timeout, headers):
        if "status.claude.com" in url:
            return httpx.Response(200, json={"incidents": []}, request=httpx.Request("GET", url))
        raise RuntimeError("synthetic status network failure")

    monkeypatch.setattr(status_monitor.network, "get_sync", unavailable)
    response = client.post(PREFIX + "/status-alerts/actions/refresh")
    assert response.status_code == 202, response.text
    failed = _terminal(client, response.json()["data"]["id"])
    assert failed["status"] == "failed" and failed["error"]["code"] == "UPSTREAM_ERROR"
    assert "openai" not in status_monitor._initialized_providers
    assert ("claude" in status_monitor._initialized_providers) is partial_success
    assert status_monitor._active["openai"] == previous_active
    history = client.get(PREFIX + "/status-alerts/incidents", params={"view": "history", "provider": "openai"})
    assert history.status_code == 502, history.text
    assert history.json()["error"]["code"] == "UPSTREAM_ERROR"

    control = runtime.control_owner().auxiliary.status_alerts
    assert control.refresh_direct(_telegram_context()) == len(targets)
    assert control.recent_direct(_telegram_context(), "openai") == []
    assert "openai" in status_monitor._initialized_providers

    def empty_feed(url, *, timeout, headers):
        return httpx.Response(200, json={"incidents": []}, request=httpx.Request("GET", url))

    monkeypatch.setattr(status_monitor.network, "get_sync", empty_feed)
    response = client.post(PREFIX + "/status-alerts/actions/refresh")
    succeeded = _terminal(client, response.json()["data"]["id"])
    assert succeeded["status"] == "succeeded"
    assert succeeded["result"]["refreshedProviders"] == targets
    empty_history = client.get(PREFIX + "/status-alerts/incidents", params={"view": "history", "provider": "openai"})
    assert empty_history.status_code == 200, empty_history.text
    assert empty_history.json()["data"]["items"] == []

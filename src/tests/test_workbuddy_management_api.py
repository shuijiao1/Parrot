"""WorkBuddy management HTTP contracts against the real shared control/ledger."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from src import config, oauth_manager as om
from src.management_api.routers.oauth import router
from src.management_api.routers.oauth_support import get_oauth_control_dependency
from src.management_control.oauth import OAuthControl
from src.oauth.workbuddy import common
from src.tests.management_oauth_fakes import ImmediateExecutor
from src.tests.test_management_api_foundation import build_app, bearer, create_session
from src.tests.test_workbuddy_actions import action_env
from src.tests.test_workbuddy_lifecycle import account


@pytest.fixture
def api(action_env, tmp_path, monkeypatch):
    key, state = action_env
    clock = [datetime.now(timezone.utc)]
    control = OAuthControl(clock=lambda: clock[0], executor=ImmediateExecutor())
    monkeypatch.setattr(control, "_post_save_account_effects", lambda *a, **k: {})
    monkeypatch.setattr(control.backend, "workbuddy_start_login", lambda: {
        "realm": "cn", "status": "pending", "auth_url": "https://www.codebuddy.cn/login", "state": "fixture-state"})
    monkeypatch.setattr(control.backend, "workbuddy_poll_login", lambda p: None)
    app, runtime, _ = build_app(tmp_path)
    app.include_router(router, prefix="/api/management/v1")
    app.dependency_overrides[get_oauth_control_dependency] = lambda: control
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        def call(method, path, body=None, extra=None):
            return client.request(method, "/api/management/v1" + path, json=body, headers={**headers, **(extra or {})})
        yield call, key, state, control, clock, runtime


def test_poll_complete_cancel_expiry_and_no_credential_echo(api, monkeypatch):
    call, key, state, ctl, clock, _ = api
    started = call("POST", "/oauth/login-flows", {"provider": "workbuddy", "realm": "cn", "clientProfile": "cli"})
    assert started.status_code == 201, started.text
    flow = started.json()["data"]
    path = "/oauth/login-flows/" + flow["flowId"]
    body = {"flowSecret": flow["flowSecret"]}
    for _ in range(2):
        pending = call("POST", path + "/poll", body)
        assert pending.status_code == 200 and pending.json()["data"]["status"] == "pending"
    assert call("POST", path + "/complete", dict(body, completed=True)).status_code == 400
    monkeypatch.setattr(ctl.backend, "workbuddy_poll_login", lambda p: p.update(status="ready", entry=dict(om.get_account(key), uid="new-fixture-uid")))
    clock[0] += timedelta(seconds=3)
    ready = call("POST", path + "/poll", body)
    assert ready.status_code == 200 and ready.json()["data"]["status"] == "ready"
    assert "fixture-at" not in ready.text and "fixture-rt" not in ready.text
    assert call("POST", path + "/complete", dict(body, completed=True)).status_code == 200
    assert call("POST", path + "/poll", body).json()["data"]["status"] == "completed"
    assert call("POST", path + "/complete", dict(body, completed=True)).status_code == 400
    flow = call("POST", "/oauth/login-flows", {"provider": "workbuddy"}).json()["data"]
    path, body = "/oauth/login-flows/" + flow["flowId"], {"flowSecret": flow["flowSecret"]}
    assert call("POST", path + "/cancel", {"flowSecret": "wrong-secret-value"}).status_code == 400
    for _ in range(2):
        result = call("POST", path + "/cancel", body)
        assert result.status_code == 204 and not result.content
    assert call("POST", path + "/poll", body).json()["data"]["status"] == "cancelled"
    flow = call("POST", "/oauth/login-flows", {"provider": "workbuddy"}).json()["data"]
    clock[0] += timedelta(seconds=301)
    assert call("POST", "/oauth/login-flows/" + flow["flowId"] + "/poll", {"flowSecret": flow["flowSecret"]}).json()["data"]["status"] == "expired"
    assert state["calls"] == 0


@pytest.mark.parametrize("body,status", [
    ({"provider": "workbuddy", "realm": "global", "clientProfile": "cli"}, 422),
    ({"provider": "openai", "realm": "cn"}, 422),
    ({"provider": "workbuddy", "clientProfile": "web"}, 422),
])
def test_login_profile_validation(api, body, status):
    response = api[0]("POST", "/oauth/login-flows", body)
    assert response.status_code == status, response.text


def test_views_policy_settings_cas_and_refresh_status(api, monkeypatch):
    call, key, state, ctl, _, runtime = api
    path = f"/oauth/accounts/{key}/workbuddy"
    view = call("GET", path)
    assert view.status_code == 200 and view.json()["data"]["snapshot"]["realm"] == "cn"
    assert "fixture-at" not in view.text and "fixture-rt" not in view.text
    policy = call("GET", "/oauth/workbuddy/settings").json()["data"]
    assert policy["autoCheckinDefault"] is False and policy["autoTrial"] is False
    detail = call("GET", f"/oauth/accounts/{key}")
    assert detail.status_code == 200, detail.text
    revision = detail.json()["data"]["account"]["revision"]
    changed = call("PATCH", path + "/settings", {"autoCheckin": True}, {"If-Match": revision})
    assert changed.status_code == 200 and changed.json()["data"]["scheduledTime"] == "09:05"
    assert call("PATCH", path + "/settings", {"autoCheckin": False}, {"If-Match": revision}).status_code == 409
    assert call("PATCH", path + "/settings", {"autoCheckin": "false"}).status_code == 422
    assert call("GET", path + "?unexpected=1").status_code == 422
    refreshed = call("POST", path + "/actions/refresh-status")
    assert refreshed.status_code == 202, refreshed.text
    op = refreshed.json()["data"]
    assert op["status"] in {"queued", "succeeded"}
    assert state["calls"] == 0  # reading activity/balance is not a check-in
    monkeypatch.setenv("PARROT_NO_REFRESH", "1")
    plan = call("POST", path + "/action-plans", {"action": "checkin"})
    assert plan.status_code == 200, plan.text
    assert call("GET", path).json()["data"]["snapshot"]["effectsEnabled"] is True
    assert state["calls"] == 0
    result = call("POST", path + "/actions/execute", {"planToken": plan.json()["data"]["planToken"]})
    assert result.status_code == 202 and state["calls"] == 1


def test_action_plan_execute_records_and_no_replay(api):
    call, key, state, _, _, _ = api
    path = f"/oauth/accounts/{key}/workbuddy"
    planned = call("POST", path + "/action-plans", {"action": "checkin"})
    assert planned.status_code == 200, planned.text
    assert planned.headers["cache-control"] == "no-store"
    token = planned.json()["data"]["planToken"]
    assert state["calls"] == 0
    executed = call("POST", path + "/actions/execute", {"planToken": token})
    assert executed.status_code == 202, executed.text
    assert state["calls"] == 1
    assert call("POST", path + "/actions/execute", {"planToken": token}).status_code == 400
    records = call("GET", path + "/action-records?page=1&pageSize=1")
    assert records.status_code == 200, records.text
    value = records.json()["data"]
    assert value["total"] == 1 and value["hasNext"] is False
    assert value["items"][0]["status"] == "succeeded" and value["items"][0]["awardedCredits"] == 3
    assert call("GET", path + "/action-records?page=2&pageSize=1").json()["data"]["items"] == []
    assert "fixture-at" not in records.text and "fixture-rt" not in records.text and token not in records.text
    token2 = call("POST", path + "/action-plans", {"action": "checkin"}).json()["data"]["planToken"]
    assert call("POST", path + "/actions/execute", {"planToken": token2}).status_code == 202
    assert state["calls"] == 1


def test_identity_pending_is_pollable_and_never_returns_candidate_tokens(api, monkeypatch):
    call, key, _, ctl, clock, _ = api
    def partial(payload):
        payload.update(status="identity_pending", token={"accessToken": "candidate-fixture-at", "refreshToken": "candidate-fixture-rt"})
        raise OSError("fixture identity lookup failed")
    monkeypatch.setattr(ctl.backend, "workbuddy_poll_login", partial)
    flow = call("POST", "/oauth/login-flows", {"provider": "workbuddy"}).json()["data"]
    path = "/oauth/login-flows/" + flow["flowId"]
    body = {"flowSecret": flow["flowSecret"]}
    response = call("POST", path + "/poll", body)
    assert response.status_code == 200 and response.json()["data"]["status"] == "identity_pending"
    assert "candidate-fixture" not in response.text and response.json()["data"]["accountPreview"] is None
    assert call("POST", path + "/complete", dict(body, completed=True)).status_code == 400
    monkeypatch.setattr(ctl.backend, "workbuddy_poll_login", lambda p: p.update(status="ready", entry=dict(om.get_account(key))))
    clock[0] += timedelta(seconds=3)
    assert call("POST", path + "/poll", body).json()["data"]["status"] == "ready"


def test_model_catalog_input_limit_is_not_context_window(api):
    call, key, _, _, _, _ = api
    config.update(lambda c: c["oauthAccounts"][0].update(models=["wb-catalog-fixture"], account_model_catalog={"models": [
        {"id": "wb-catalog-fixture", "maxInputTokens": 100000, "maxOutputTokens": 8192, "reasoningEfforts": ["low", "high"]}]}))
    response = call("GET", f"/oauth/accounts/{key}/models")
    assert response.status_code == 200, response.text
    item = response.json()["data"]["items"][0]
    assert item["maxInputTokens"] == 100000 and item["maxOutputTokens"] == 8192
    assert item["reasoningEfforts"] == ["low", "high"] and item["contextWindow"] is None


def test_workbuddy_import_preview_keep_overwrite_and_secrets(api):
    call, key, state, _, _, _ = api
    entry = dict(om.get_account(key), access_token="import-fixture-at", refresh_token="import-fixture-rt")
    body = {"format": "workbuddy", "payload": json.dumps(entry)}
    for action in ("keep", "overwrite"):
        preview = call("POST", "/oauth/imports/preview", body)
        assert preview.status_code == 200, preview.text
        data = preview.json()["data"]
        assert len(data["candidates"]) == 1 and data["candidates"][0]["conflictAccountId"] == key
        assert "import-fixture-at" not in preview.text and "import-fixture-rt" not in preview.text
        result = call("POST", "/oauth/imports/" + data["importId"] + "/commit", {
            "importSecret": data["importSecret"], "decisions": [{"candidateId": data["candidates"][0]["candidateId"], "action": action}]})
        assert result.status_code == 200, result.text
        assert om.get_account(key)["access_token"] == ("fixture-at" if action == "keep" else "import-fixture-at")
    assert state["calls"] == 0

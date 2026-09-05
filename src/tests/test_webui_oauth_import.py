"""Real local OAuth import chain regressions for the Management WebUI API."""

from __future__ import annotations

import copy
import json
import os
from concurrent.futures import Future

import pytest
from fastapi.testclient import TestClient

from src.tests import _isolation

_isolation.isolate()

from src import config, oauth_manager, state_db  # noqa: E402
from src.management_api.routers.oauth import router as oauth_router  # noqa: E402
from src.management_api.routers.oauth_support import (  # noqa: E402
    get_oauth_control_dependency,
)
from src.management_control.errors import ManagementError, ManagementErrorCode  # noqa: E402
from src.management_control.oauth import OAuthBackend, OAuthControl  # noqa: E402
from src.management_control.oauth.models import OAuthImportDecision  # noqa: E402
from src.oauth import openai as openai_provider  # noqa: E402
from src.oauth.openai_import import (  # noqa: E402
    OpenAIImportCandidate as ParsedImportCandidate,
    parse_openai_import_payload,
)
from src.tests.test_management_api_foundation import (  # noqa: E402
    bearer,
    build_app,
    create_session,
)


def _account(email: str, workspace: str, access_token: str) -> dict:
    return {
        "email": email,
        "provider": "openai",
        "type": "openai",
        "workspace_id": workspace,
        "chatgpt_account_id": workspace,
        "access_token": access_token,
        "refresh_token": "existing-refresh-token-fake",
        "expired": "2030-01-01T00:00:00Z",
        "last_refresh": "2026-01-01T00:00:00Z",
        "enabled": True,
        "disabled_reason": None,
        "disabled_until": None,
        "models": ["kept-model"],
        "maxConcurrent": 3,
    }


def _payload(kind: str, email: str, refresh_token: str) -> str:
    if kind == "openai":
        value = {
            "provider": "openai",
            "type": "openai",
            "email": email,
            "refresh_token": refresh_token,
        }
    elif kind == "cpa":
        value = {"email": email, "refresh_token": refresh_token}
    else:
        value = {
            "accounts": [{
                "platform": "openai",
                "type": "oauth",
                "credentials": {
                    "email": email,
                    "refresh_token": refresh_token,
                },
            }]
        }
    return json.dumps(value)


def _install_private_config(tmp_path, monkeypatch, accounts: list[dict]):
    path = tmp_path / "oauth-config.json"
    initial = copy.deepcopy(config.DEFAULT_CONFIG)
    initial["oauthAccounts"] = copy.deepcopy(accounts)
    initial["stateDbPath"] = os.environ["PARROT_TEST_STATE_PATH"]
    initial["logDir"] = os.environ["PARROT_TEST_LOG_DIR"]
    initial.setdefault("oauth", {})["mockMode"] = True
    initial.setdefault("openaiOAuth", {}).update({
        "codexCliVersion": "0.153.4",
        "codexProtocolProfile": "rust-v0.153.4",
    })
    path.write_text(json.dumps(initial, ensure_ascii=False, indent=2), encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_PATH", str(path))
    monkeypatch.setattr(config, "_cache", copy.deepcopy(initial))
    monkeypatch.setattr(config, "_mtime", os.path.getmtime(path))
    monkeypatch.setattr(config, "_reload_callbacks", [])

    writes: list[dict] = []
    original_write = config._write_atomic

    def record_write(candidate: dict) -> None:
        writes.append(copy.deepcopy(candidate))
        original_write(candidate)

    monkeypatch.setattr(config, "_write_atomic", record_write)
    return path, copy.deepcopy(initial), writes


def _fake_only_supplier_edges(monkeypatch, identities: dict[str, tuple[str, str]]):
    calls = {
        "refresh": [],
        "usage": [],
        "quota_save": [],
        "quota_evaluate": [],
        "model_sync": [],
    }

    def refresh(refresh_token: str, **_kwargs) -> dict:
        calls["refresh"].append(refresh_token)
        email, workspace = identities[refresh_token]
        return {
            "access_token": f"access-for-{workspace}",
            "refresh_token": refresh_token,
            "id_token": refresh_token,
            "expires_in": 3600,
            "workspace_id": workspace,
            "chatgpt_account_id": workspace,
            "email": email,
        }

    def decode(id_token: str) -> dict:
        email, workspace = identities[id_token]
        return {
            "email": email,
            "workspace_id": workspace,
            "chatgpt_account_id": workspace,
            "workspace_name": f"Workspace {workspace}",
        }

    monkeypatch.setattr(openai_provider, "refresh_sync", refresh)
    monkeypatch.setattr(openai_provider, "decode_id_token", decode)
    monkeypatch.setattr(openai_provider, "extract_user_info", lambda claims: claims)

    async def fetch_usage(account_id: str) -> dict:
        calls["usage"].append(account_id)
        return {
            "five_hour": {
                "utilization": 10.0,
                "resets_at": "2030-01-01T01:00:00Z",
            },
            "seven_day": {
                "utilization": 20.0,
                "resets_at": "2030-01-07T00:00:00Z",
            },
        }

    monkeypatch.setattr(oauth_manager, "fetch_usage_snapshot", fetch_usage)

    original_save = state_db.quota_save

    def quota_save(account_id: str, usage: dict, **kwargs) -> None:
        calls["quota_save"].append(account_id)
        original_save(account_id, usage, **kwargs)

    monkeypatch.setattr(state_db, "quota_save", quota_save)

    original_evaluate = oauth_manager.evaluate_and_toggle_by_usage

    def evaluate(account_id: str, usage: dict, **kwargs) -> dict:
        calls["quota_evaluate"].append(account_id)
        return original_evaluate(account_id, usage, **kwargs)

    monkeypatch.setattr(oauth_manager, "evaluate_and_toggle_by_usage", evaluate)

    def model_sync(account_id: str) -> Future:
        calls["model_sync"].append(account_id)
        future = Future()
        future.set_result({"action": "updated", "models": 1})
        return future

    monkeypatch.setattr(oauth_manager, "start_account_model_refresh", model_sync)
    return calls


def _real_control_client(tmp_path, monkeypatch, accounts, identities):
    path, before, writes = _install_private_config(tmp_path, monkeypatch, accounts)
    state_db.init()
    for email, workspace in identities.values():
        state_db.quota_delete(f"openai:{email}:{workspace}")
    calls = _fake_only_supplier_edges(monkeypatch, identities)
    control = OAuthControl()
    assert type(control.backend) is OAuthBackend

    app, runtime, _notifier = build_app(tmp_path)
    app.include_router(oauth_router, prefix="/api/management/v1")
    app.dependency_overrides[get_oauth_control_dependency] = lambda: control
    app.openapi_schema = None
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    headers = bearer(create_session(client))
    return client, headers, runtime, control, calls, writes, path, before


def _preview(client, headers, kind: str, email: str, refresh_token: str):
    return client.post(
        "/api/management/v1/oauth/imports/preview",
        json={
            "format": kind,
            "payload": _payload(kind, email, refresh_token),
            "filename": f"{kind}.json",
        },
        headers=headers,
    )


def _commit(client, headers, preview: dict, action: str):
    return client.post(
        f"/api/management/v1/oauth/imports/{preview['importId']}/commit",
        json={
            "importSecret": preview["importSecret"],
            "decisions": [{
                "candidateId": preview["candidates"][0]["candidateId"],
                "action": action,
            }],
        },
        headers=headers,
    )


@pytest.mark.parametrize("kind", ["openai", "cpa", "sub2api"])
def test_real_backend_asgi_preview_commit_supports_all_documented_formats(
    tmp_path, monkeypatch, kind,
):
    email = f"webui-{kind}@example.test"
    workspace = f"workspace-{kind}"
    refresh_token = f"refresh-{kind}-token-12345678901234567890"
    client, headers, _runtime, _control, calls, writes, path, before = (
        _real_control_client(
            tmp_path, monkeypatch, [], {refresh_token: (email, workspace)},
        )
    )
    account_id = f"openai:{email}:{workspace}"
    try:
        preview_response = _preview(client, headers, kind, email, refresh_token)
        assert preview_response.status_code == 200, preview_response.text
        preview = preview_response.json()["data"]
        assert preview["errors"] == []
        assert preview["candidates"] == [{
            "candidateId": "candidate-1",
            "provider": "openai",
            "identity": account_id,
            "displayName": email,
            "conflictAccountId": None,
        }]
        assert refresh_token not in preview_response.text
        assert config.get() == before
        assert json.loads(path.read_text(encoding="utf-8")) == before
        assert writes == []
        assert state_db.quota_load(account_id) is None
        assert calls == {
            "refresh": [refresh_token],
            "usage": [],
            "quota_save": [],
            "quota_evaluate": [],
            "model_sync": [],
        }

        committed = _commit(client, headers, preview, "overwrite")
        assert committed.status_code == 200, committed.text
        assert committed.json()["data"] == {
            "added": [account_id], "replaced": [], "skipped": [],
        }
        assert len(writes) == 1
        assert json.loads(path.read_text(encoding="utf-8")) == config.get()
        account = oauth_manager.get_account(account_id)
        assert account["access_token"] == f"access-for-{workspace}"
        quota = state_db.quota_load(account_id)
        assert quota is not None and quota["five_hour_util"] == 10.0
        assert calls["model_sync"] == [account_id]
        assert calls["usage"] == [account_id]
        assert calls["quota_save"] == [account_id]
        assert calls["quota_evaluate"] == [account_id]

        replay = _commit(client, headers, preview, "overwrite")
        assert replay.status_code == 400
        assert replay.json()["error"]["code"] == "INVALID_OPERATION_STATE"
        assert len(writes) == 1
    finally:
        client.__exit__(None, None, None)


def test_real_backend_conflict_keep_then_overwrite_and_post_effect_counts(
    tmp_path, monkeypatch,
):
    email = "webui-conflict@example.test"
    workspace = "workspace-conflict"
    refresh_token = "refresh-conflict-token-12345678901234567890"
    existing = _account(email, workspace, "old-access")
    client, headers, _runtime, _control, calls, writes, _path, before = (
        _real_control_client(
            tmp_path, monkeypatch, [existing], {refresh_token: (email, workspace)},
        )
    )
    account_id = f"openai:{email}:{workspace}"
    try:
        keep_preview = _preview(client, headers, "openai", email, refresh_token).json()["data"]
        assert keep_preview["candidates"][0]["conflictAccountId"] == account_id
        kept = _commit(client, headers, keep_preview, "keep")
        assert kept.status_code == 200, kept.text
        assert kept.json()["data"] == {
            "added": [], "replaced": [], "skipped": [account_id],
        }
        assert config.get() == before
        assert writes == []
        assert calls["usage"] == calls["quota_save"] == []
        assert calls["quota_evaluate"] == calls["model_sync"] == []

        overwrite_preview = _preview(
            client, headers, "openai", email, refresh_token,
        ).json()["data"]
        overwritten = _commit(client, headers, overwrite_preview, "overwrite")
        assert overwritten.status_code == 200, overwritten.text
        assert overwritten.json()["data"] == {
            "added": [], "replaced": [account_id], "skipped": [],
        }
        assert len(writes) == 1
        account = oauth_manager.get_account(account_id)
        assert account["access_token"] == f"access-for-{workspace}"
        assert account["models"] == ["kept-model"]
        assert account["maxConcurrent"] == 3
        assert state_db.quota_load(account_id)["seven_day_util"] == 20.0
        assert calls["model_sync"] == [account_id]
        assert calls["usage"] == [account_id]
        assert calls["quota_save"] == [account_id]
        assert calls["quota_evaluate"] == [account_id]
    finally:
        client.__exit__(None, None, None)


def test_real_backend_cas_conflict_and_invalid_input_publish_nothing(
    tmp_path, monkeypatch,
):
    email = "webui-cas@example.test"
    workspace = "workspace-cas"
    refresh_token = "refresh-cas-token-12345678901234567890"
    client, headers, _runtime, _control, calls, writes, path, before = (
        _real_control_client(
            tmp_path, monkeypatch, [], {refresh_token: (email, workspace)},
        )
    )
    try:
        invalid = client.post(
            "/api/management/v1/oauth/imports/preview",
            json={"format": "openai", "payload": "not-json"},
            headers=headers,
        )
        assert invalid.status_code == 200, invalid.text
        assert invalid.json()["data"]["candidates"] == []
        assert invalid.json()["data"]["errors"][0]["code"] == "PARSE_FAILED"
        assert config.get() == before and writes == []

        preview = _preview(client, headers, "cpa", email, refresh_token).json()["data"]
        config._cache["oauthAccounts"].append(
            _account("concurrent@example.test", "concurrent-workspace", "concurrent-access")
        )
        stale_snapshot = copy.deepcopy(config.get())
        committed = _commit(client, headers, preview, "overwrite")
        assert committed.status_code == 409, committed.text
        assert committed.json()["error"]["code"] == "REVISION_CONFLICT"
        assert config.get() == stale_snapshot
        assert json.loads(path.read_text(encoding="utf-8")) == before
        assert writes == []
        assert calls["usage"] == calls["quota_save"] == []
        assert calls["quota_evaluate"] == calls["model_sync"] == []
    finally:
        client.__exit__(None, None, None)


def test_post_publish_usage_failure_does_not_roll_back_credentials(
    tmp_path, monkeypatch,
):
    email = "webui-post-failure@example.test"
    workspace = "workspace-post-failure"
    refresh_token = "refresh-post-failure-token-12345678901234567890"
    client, headers, _runtime, _control, calls, writes, _path, _before = (
        _real_control_client(
            tmp_path, monkeypatch, [], {refresh_token: (email, workspace)},
        )
    )
    account_id = f"openai:{email}:{workspace}"

    async def failed_usage(target: str) -> dict:
        calls["usage"].append(target)
        raise RuntimeError("fake supplier usage failure")

    monkeypatch.setattr(oauth_manager, "fetch_usage_snapshot", failed_usage)
    try:
        preview = _preview(
            client, headers, "openai", email, refresh_token,
        ).json()["data"]
        committed = _commit(client, headers, preview, "overwrite")
        assert committed.status_code == 200, committed.text
        assert committed.json()["data"]["added"] == [account_id]
        assert oauth_manager.get_account(account_id)["access_token"] == (
            f"access-for-{workspace}"
        )
        assert len(writes) == 1
        assert calls["model_sync"] == [account_id]
        assert calls["usage"] == [account_id]
        assert calls["quota_save"] == []
        assert calls["quota_evaluate"] == []
    finally:
        client.__exit__(None, None, None)


def test_real_backend_second_item_failure_discards_whole_candidate(
    tmp_path, monkeypatch,
):
    first = "refresh-first-token-12345678901234567890"
    second = "refresh-second-token-12345678901234567890"
    identities = {
        first: ("webui-first@example.test", "workspace-first"),
        second: ("webui-second@example.test", "workspace-second"),
    }
    _path, before, writes = _install_private_config(tmp_path, monkeypatch, [])
    state_db.init()
    calls = _fake_only_supplier_edges(monkeypatch, identities)
    control = OAuthControl()
    from src.management_control.oauth.menu_bridge import telegram_context

    context = telegram_context(42)
    preview = control.preview_import(
        context,
        format="openai",
        payload=json.dumps([
            {"email": identities[first][0], "refresh_token": first},
            {"email": identities[second][0], "refresh_token": second},
        ]),
    )
    assert len(preview.candidates) == 2
    original_apply = oauth_manager._apply_import_candidate_to_config
    applied: list[str] = []

    def fail_second(candidate_config, item, choice):
        applied.append(item["candidate_id"])
        if len(applied) == 2:
            raise RuntimeError("injected second candidate failure")
        return original_apply(candidate_config, item, choice)

    monkeypatch.setattr(oauth_manager, "_apply_import_candidate_to_config", fail_second)
    decisions = tuple(
        OAuthImportDecision(item.candidate_id, "overwrite")
        for item in preview.candidates
    )
    with pytest.raises(RuntimeError, match="second candidate failure"):
        control.commit_import(
            context, preview.import_id, preview.import_secret, decisions,
        )

    assert applied == ["candidate-1", "candidate-2"]
    assert config.get() == before
    assert writes == []
    assert oauth_manager.list_accounts() == []
    assert calls["usage"] == calls["quota_save"] == []
    assert calls["quota_evaluate"] == calls["model_sync"] == []


def test_native_openai_parser_returns_unprepared_secret_candidate():
    refresh_token = "native-openai-refresh-token-12345678901234567890"
    parsed = parse_openai_import_payload(
        "openai",
        json.dumps({
            "provider": "openai",
            "type": "openai",
            "email": "native@example.test",
            "refresh_token": refresh_token,
        }),
        filename="openai.json",
    )
    assert parsed == [
        ParsedImportCandidate(
            email="native@example.test",
            refresh_token=refresh_token,
            source="openai.json",
        )
    ]

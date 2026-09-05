from __future__ import annotations

import json
import os
import sqlite3
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from src import config
from src.management_auth import Capability, ManagementStateStore
from src.management_control import ManagementError
from src.management_control.apikey import ApiKeyControl, ApiKeyProvenance, ApiKeySource
from src.tests.test_management_apikey_api import build_app, session_headers
from src.tests.test_management_apikey_control import (
    FakeModels,
    FakeStats,
    Sequence,
    context,
    make_control,
)


def _entry(secret: str, *, source: str | None = None) -> dict:
    result = {
        "key": secret,
        "enabled": True,
        "allowedModels": [],
        "allowImages": False,
        "allowVideos": False,
    }
    if source is not None:
        result["source"] = source
    return result


def _provenance_rows(store: ManagementStateStore) -> list[tuple[str, str]]:
    with sqlite3.connect(store.path) as connection:
        return connection.execute(
            "SELECT key,value FROM metadata "
            "WHERE key LIKE 'apiKeyProvenance:%' ORDER BY key"
        ).fetchall()


def _real_config_app(tmp_path, monkeypatch, initial: dict, *, generated=None):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(initial), encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(config, "_cache", deepcopy(initial))
    monkeypatch.setattr(config, "_mtime", os.path.getmtime(config_path))
    monkeypatch.setattr(config, "_reload_callbacks", [])

    app, runtime, _, _, limiter = build_app(tmp_path)
    control = ApiKeyControl(
        config_store=config,
        provenance_store=runtime.state_store,
        limiter=limiter,
        statistics=FakeStats(),
        model_registry=FakeModels(),
        generated_secret_factory=generated or Sequence(["ccp-" + "n" * 48]),
    )
    app.state.management_apikey_control = control
    return app, runtime, control


def test_real_asgi_rejected_duplicate_create_preserves_committed_source(
    tmp_path, monkeypatch,
):
    app, runtime, _, = _real_config_app(
        tmp_path,
        monkeypatch,
        {"apiKeys": {}, "xaiOAuth": {"imageModels": [], "videoModels": []}},
    )
    client = TestClient(app)
    headers = session_headers(runtime)
    try:
        created = client.post(
            "/api/management/v1/api-keys",
            headers=headers,
            json={
                "mode": "custom",
                "name": "stable",
                "customSecret": "stable-custom-secret",
            },
        )
        assert created.status_code == 201, created.text
        before_config = deepcopy(config.get())
        before_rows = _provenance_rows(runtime.state_store)

        rejected = client.post(
            "/api/management/v1/api-keys",
            headers=headers,
            json={
                "mode": "custom",
                "name": "stable",
                "customSecret": "different-custom-secret",
            },
        )
        assert rejected.status_code == 409, rejected.text
        assert config.get() == before_config
        assert _provenance_rows(runtime.state_store) == before_rows

        detail = client.get(
            "/api/management/v1/api-keys/stable", headers=headers,
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["data"]["source"] == "custom"
    finally:
        runtime.close()


def test_real_asgi_legacy_config_source_is_read_only_and_survives_rebuild(
    tmp_path, monkeypatch,
):
    initial = {
        "apiKeys": {"legacy": _entry("legacy-custom-secret", source="custom")},
        "xaiOAuth": {"imageModels": [], "videoModels": []},
    }
    app, runtime, control = _real_config_app(tmp_path, monkeypatch, initial)
    client = TestClient(app)
    headers = session_headers(runtime)
    try:
        before_rows = _provenance_rows(runtime.state_store)
        assert before_rows == []

        detail = client.get(
            "/api/management/v1/api-keys/legacy", headers=headers,
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["data"]["source"] == "custom"

        assert _provenance_rows(runtime.state_store) == before_rows
        assert config.get() == initial

        rebuilt = ApiKeyControl(
            config_store=config,
            provenance_store=runtime.state_store,
            limiter=control._limiter,
            statistics=FakeStats(),
            model_registry=FakeModels(),
        )
        app.state.management_apikey_control = rebuilt
        after_rebuild = client.get(
            "/api/management/v1/api-keys/legacy", headers=headers,
        )
        assert after_rebuild.status_code == 200, after_rebuild.text
        assert after_rebuild.json()["data"]["source"] == "custom"
        assert _provenance_rows(runtime.state_store) == before_rows
    finally:
        runtime.close()


_REJECTION_CASES = (
    "permission-create",
    "duplicate-name-create",
    "duplicate-secret-create",
    "permission-replace",
    "missing-replace",
    "stale-replace",
    "duplicate-secret-replace",
    "wrong-actor-plan",
    "stale-plan",
    "permission-delete",
    "missing-delete",
    "stale-delete",
)


@pytest.mark.parametrize("case", _REJECTION_CASES)
def test_rejected_mutations_preserve_config_and_all_provenance_rows(tmp_path, case):
    state_store = ManagementStateStore(
        str(tmp_path / f"rejected-{case}.db"), clock=lambda: 1_788_557_400.0,
    )
    control, config_store, _, _ = make_control(
        {"apiKeys": {}, "xaiOAuth": {"imageModels": [], "videoModels": []}},
        generated=Sequence(["ccp-" + "g" * 48]),
        tokens=Sequence(["plan-id", "plan-token"]),
        provenance_store=state_store,
    )
    secrets_write = context(Capability.SECRETS_WRITE, subject="owner")
    destructive = context(Capability.DESTRUCTIVE, subject="owner")
    read = context(Capability.READ)
    try:
        stable = control.create_api_key(
            secrets_write,
            name="stable",
            mode=ApiKeySource.CUSTOM,
            custom_secret="stable-custom-secret",
        )
        control.create_api_key(
            secrets_write,
            name="occupied",
            mode=ApiKeySource.CUSTOM,
            custom_secret="occupied-custom-secret",
        )

        expected_code = "CAPABILITY_DENIED"
        if case == "permission-create":
            call = lambda: control.create_api_key(
                context(),
                name="denied",
                mode=ApiKeySource.CUSTOM,
                custom_secret="denied-custom-secret",
            )
        elif case == "duplicate-name-create":
            expected_code = "RESOURCE_CONFLICT"
            call = lambda: control.create_api_key(
                secrets_write,
                name="stable",
                mode=ApiKeySource.CUSTOM,
                custom_secret="different-custom-secret",
            )
        elif case == "duplicate-secret-create":
            expected_code = "RESOURCE_CONFLICT"
            call = lambda: control.create_api_key(
                secrets_write,
                name="new-name",
                mode=ApiKeySource.CUSTOM,
                custom_secret="occupied-custom-secret",
            )
        elif case == "permission-replace":
            call = lambda: control.replace_api_key_secret(
                context(),
                "stable",
                custom_secret="replacement-custom-secret",
                if_match=stable.api_key.revision,
            )
        elif case == "missing-replace":
            expected_code = "RESOURCE_NOT_FOUND"
            call = lambda: control.replace_api_key_secret(
                secrets_write,
                "missing",
                custom_secret="replacement-custom-secret",
                if_match=None,
                require_revision=False,
            )
        elif case == "stale-replace":
            expected_code = "REVISION_CONFLICT"
            call = lambda: control.replace_api_key_secret(
                secrets_write,
                "stable",
                custom_secret="replacement-custom-secret",
                if_match='"ak-stale"',
            )
        elif case == "duplicate-secret-replace":
            expected_code = "RESOURCE_CONFLICT"
            call = lambda: control.replace_api_key_secret(
                secrets_write,
                "stable",
                custom_secret="occupied-custom-secret",
                if_match=stable.api_key.revision,
            )
        elif case == "wrong-actor-plan":
            plan = control.plan_regeneration(secrets_write, "stable")
            call = lambda: control.regenerate_api_key(
                context(Capability.SECRETS_WRITE, subject="other"),
                "stable",
                plan_id=plan.plan_id,
                plan_token=plan.plan_token,
            )
        elif case == "stale-plan":
            plan = control.plan_regeneration(secrets_write, "stable")
            control.update_api_key(
                context(Capability.WRITE),
                "stable",
                changes={"enabled": False},
                if_match=stable.api_key.revision,
            )
            expected_code = "REVISION_CONFLICT"
            call = lambda: control.regenerate_api_key(
                secrets_write,
                "stable",
                plan_id=plan.plan_id,
                plan_token=plan.plan_token,
            )
        elif case == "permission-delete":
            call = lambda: control.delete_api_key(
                context(), "stable", if_match=stable.api_key.revision,
            )
        elif case == "missing-delete":
            expected_code = "RESOURCE_NOT_FOUND"
            call = lambda: control.delete_api_key(
                destructive, "missing", if_match='"ak-any"',
            )
        else:
            expected_code = "REVISION_CONFLICT"
            call = lambda: control.delete_api_key(
                destructive, "stable", if_match='"ak-stale"',
            )

        before_config = deepcopy(config_store.value)
        before_rows = _provenance_rows(state_store)
        with pytest.raises(ManagementError) as caught:
            call()
        assert caught.value.code.value == expected_code
        assert config_store.value == before_config
        assert _provenance_rows(state_store) == before_rows
        assert control.get_api_key(read, "stable").source is ApiKeyProvenance.CUSTOM
        assert control.get_api_key(read, "occupied").source is ApiKeyProvenance.CUSTOM
    finally:
        state_store.close()


def test_explicit_source_is_authoritative_and_unknown_is_not_guessed(tmp_path):
    store = ManagementStateStore(str(tmp_path / "source-read.db"), clock=lambda: 1_788_557_400.0)
    control, _, _, _ = make_control(
        {"apiKeys": {
            "known": _entry("known-custom-secret", source="custom"),
            "unknown": _entry("ccp-prefix-is-not-proof"),
        }},
        provenance_store=store,
    )
    try:
        before = _provenance_rows(store)
        assert control.get_api_key(context(Capability.READ), "known").source is ApiKeyProvenance.CUSTOM
        assert control.get_api_key(context(Capability.READ), "unknown").source is ApiKeyProvenance.UNKNOWN
        assert _provenance_rows(store) == before
    finally:
        store.close()


def test_successful_source_changes_update_config_side_record_and_reopen(tmp_path):
    database = tmp_path / "source-change.db"
    state_store = ManagementStateStore(
        str(database), clock=lambda: 1_788_557_400.0,
    )
    control, config_store, limiter, _ = make_control(
        {"apiKeys": {}, "xaiOAuth": {"imageModels": [], "videoModels": []}},
        generated=Sequence(["ccp-" + "r" * 48]),
        provenance_store=state_store,
    )
    secrets_write = context(Capability.SECRETS_WRITE)
    read = context(Capability.READ)
    created = control.create_api_key(
        secrets_write,
        name="changing",
        mode=ApiKeySource.CUSTOM,
        custom_secret="initial-custom-secret",
    )
    assert config_store.value["apiKeys"]["changing"]["source"] == "custom"
    changed = control.regenerate_api_key(
        secrets_write, "changing", require_plan=False, reset_runtime=False,
    )
    assert changed.api_key.source is ApiKeyProvenance.GENERATED
    assert config_store.value["apiKeys"]["changing"]["key"] == changed.secret
    assert config_store.value["apiKeys"]["changing"]["source"] == "generated"
    state_store.close()

    reopened = ManagementStateStore(
        str(database), clock=lambda: 1_788_557_401.0,
    )
    try:
        rebuilt = ApiKeyControl(
            config_store=config_store,
            provenance_store=reopened,
            limiter=limiter,
            statistics=FakeStats(),
            model_registry=FakeModels(),
        )
        assert rebuilt.get_api_key(read, "changing").source is ApiKeyProvenance.GENERATED
        assert rebuilt.get_api_key(read, "changing").revision == changed.api_key.revision
        assert created.secret == "initial-custom-secret"
    finally:
        reopened.close()

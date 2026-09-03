from __future__ import annotations

from fastapi.testclient import TestClient

from src.tests.management_auxiliary_support import (
    TRANSLATION_LANGUAGES,
    bearer,
    build_auxiliary_app,
    create_session,
)


BASE = "/api/management/v1"


def test_translation_all_operations_revision_operation_and_side_effects(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        token = create_session(client)
        headers = bearer(token)

        initial = client.get(BASE + "/translation", headers=headers)
        assert initial.status_code == 200
        data = initial.json()["data"]
        assert data["model"] == "model-a"
        assert data["scope"] == {"models": [], "channels": []}
        assert isinstance(data["revision"], str)

        updated = client.patch(
            BASE + "/translation",
            json={
                "enabled": True,
                "fallbackModel": "model-b",
                "targetLanguage": "Japanese",
                "scope": {"models": ["business-model"], "channels": ["api:one"]},
                "modelOverrides": {"model-a": {"body": {"temperature": 0}}},
                "prompt": "Translate to {target_language}",
            },
            headers={**headers, "If-Match": data["revision"]},
        )
        assert updated.status_code == 200, updated.text
        changed = updated.json()["data"]
        assert changed["enabled"] is True
        assert changed["targetLanguage"] == "Japanese"
        assert changed["modelOverrides"]["model-a"]["body"] == {"temperature": 0}
        assert fixture.config.value["translation"]["fallbackModel"] == "model-b"

        stale = client.patch(
            BASE + "/translation",
            json={"enabled": False},
            headers={**headers, "If-Match": data["revision"]},
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "REVISION_CONFLICT"

        cache = client.get(BASE + "/translation/cache", headers=headers)
        assert cache.status_code == 200
        assert cache.json()["data"]["entries"] == 3
        assert client.delete(BASE + "/translation/cache", headers=headers).status_code == 204
        assert fixture.translation_gateway.clear_calls == 1

        languages = client.get(BASE + "/translation/languages", headers=headers)
        assert languages.status_code == 200
        assert languages.json()["data"]["total"] == len(TRANSLATION_LANGUAGES)

        started = client.post(
            BASE + "/translation/actions/test",
            json={"text": "hello"},
            headers=headers,
        )
        assert started.status_code == 202
        operation_id = started.json()["data"]["id"]
        terminal = client.get(BASE + f"/operations/{operation_id}", headers=headers)
        assert terminal.status_code == 200
        assert terminal.json()["data"]["status"] == "succeeded"
        assert terminal.json()["data"]["result"]["translated"] == "translated"
        assert fixture.translation_gateway.test_calls == ["hello"]

    actors = {record.actor for record in fixture.audit.snapshot()}
    assert actors == {"administrator"}


def test_translation_reserved_override_and_failed_operation_have_stable_errors(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        invalid = client.patch(
            BASE + "/translation",
            json={"modelOverrides": {"model-a": {"body": {"_parrot_secret": True}}}},
            headers=headers,
        )
        assert invalid.status_code == 422
        assert invalid.json()["error"]["fields"][0]["code"] == "RESERVED_FIELD"

        async def failed(_text):
            return {"ok": False, "reason": "upstream included token=secret"}

        fixture.translation_gateway.test_text = failed
        started = client.post(
            BASE + "/translation/actions/test",
            json={"text": "hello"},
            headers=headers,
        )
        operation = client.get(
            BASE + f"/operations/{started.json()['data']['id']}",
            headers=headers,
        ).json()["data"]
        assert operation["status"] == "failed"
        assert operation["error"]["code"] == "UPSTREAM_ERROR"
        assert "token=secret" not in str(operation)


def test_status_all_operations_list_filters_paging_revision_and_missing(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        initial = client.get(BASE + "/status-alerts/settings", headers=headers)
        assert initial.status_code == 200
        revision = initial.json()["data"]["revision"]

        updated = client.patch(
            BASE + "/status-alerts/settings",
            json={"intervalSeconds": 120, "targets": ["claude", "openai"]},
            headers={**headers, "If-Match": revision},
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["targets"] == ["claude", "openai"]
        assert fixture.status_gateway.forgotten == ["cloudflare"]

        listed = client.get(
            BASE + "/status-alerts/incidents",
            params={"view": "active", "provider": "claude", "sort": "createdAtAsc", "page": 1, "pageSize": 1},
            headers=headers,
        )
        assert listed.status_code == 200
        incident = listed.json()["data"]["items"][0]
        assert listed.json()["meta"] == {
            "requestId": listed.json()["meta"]["requestId"],
            "page": 1,
            "pageSize": 1,
            "total": 1,
            "hasNext": False,
        }
        assert incident["id"] == "inc-1"
        assert incident["createdAt"] == "2026-01-02T03:04:05Z"
        assert incident["updatedAt"] == "2026-01-02T03:05:05Z"
        assert incident["revision"].startswith("rev_")

        muted = client.post(
            BASE + "/status-alerts/incidents/inc-1/actions/mute",
            headers={**headers, "If-Match": incident["revision"]},
        )
        assert muted.status_code == 200
        muted_data = muted.json()["data"]
        assert muted_data["muted"] is True
        assert muted_data["mutedAt"] == "1970-01-01T00:16:40Z"
        muted_list = client.get(
            BASE + "/status-alerts/incidents?view=muted&pageSize=1",
            headers=headers,
        )
        assert muted_list.status_code == 200
        assert muted_list.json()["meta"]["total"] == 1
        listed_muted = muted_list.json()["data"]["items"][0]
        assert listed_muted["id"] == "inc-1"
        assert listed_muted["revision"] == muted_data["revision"]

        unmuted = client.delete(
            BASE + "/status-alerts/incidents/inc-1/mute",
            headers={**headers, "If-Match": muted_data["revision"]},
        )
        assert unmuted.status_code == 204
        missing = client.delete(BASE + "/status-alerts/incidents/missing/mute", headers=headers)
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

        history = client.get(
            BASE + "/status-alerts/incidents?view=history&impact=major",
            headers=headers,
        )
        assert history.status_code == 200

        refreshed = client.post(BASE + "/status-alerts/actions/refresh", headers=headers)
        assert refreshed.status_code == 202
        operation = client.get(
            BASE + f"/operations/{refreshed.json()['data']['id']}",
            headers=headers,
        ).json()["data"]
        assert operation["status"] == "succeeded"
        assert operation["result"]["refreshedProviders"] == ["claude", "openai"]


def test_status_list_rejects_unknown_filter(tmp_path):
    app, _, _ = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(
            BASE + "/status-alerts/incidents?view=unknown",
            headers=headers,
        )
        assert response.status_code == 422
        assert any(item["path"] == "view" for item in response.json()["error"]["fields"])


def test_status_public_times_convert_offsets_and_invalid_values_to_utc_or_null(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    fixture.status_gateway.active["claude"][0]["created_at"] = "2026-01-02T11:04:05+08:00"
    fixture.status_gateway.active["claude"][0]["updated_at"] = 1767323105
    fixture.status_gateway.muted.append({
        "provider": "openai",
        "incident_id": "muted-invalid-time",
        "name": "Muted",
        "muted_at": "not-a-time",
        "created_at": "also-not-a-time",
        "updated_at": None,
    })
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        active = client.get(
            BASE + "/status-alerts/incidents?view=active&provider=claude",
            headers=headers,
        ).json()["data"]["items"][0]
        assert active["createdAt"] == "2026-01-02T03:04:05Z"
        assert active["updatedAt"] == "2026-01-02T03:05:05Z"

        muted = client.get(
            BASE + "/status-alerts/incidents?view=muted&provider=openai",
            headers=headers,
        ).json()["data"]["items"][0]
        assert muted["createdAt"] is None
        assert muted["updatedAt"] is None
        assert muted["mutedAt"] is None

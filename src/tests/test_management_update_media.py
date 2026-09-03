from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from src.tests.management_auxiliary_support import bearer, build_auxiliary_app, create_session


BASE = "/api/management/v1"


def _poll(client, headers, operation_id):
    response = client.get(BASE + f"/operations/{operation_id}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_update_all_operations_prepare_commit_polling_and_replay(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        initial = client.get(BASE + "/updates/settings", headers=headers)
        assert initial.status_code == 200
        revision = initial.json()["data"]["revision"]

        updated = client.patch(
            BASE + "/updates/settings",
            json={"enabled": False, "intervalSeconds": 7200},
            headers={**headers, "If-Match": revision},
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["intervalSeconds"] == 7200

        checked = client.post(BASE + "/updates/actions/check", headers=headers)
        assert checked.status_code == 200
        assert checked.json()["data"]["candidateVersion"] == "0.32.0"
        assert checked.json()["data"]["changelog"] == "changes"

        ignored = client.put(BASE + "/updates/ignored-versions/0.32.0", headers=headers)
        assert ignored.status_code == 200
        assert ignored.json()["data"]["ignoredVersions"] == ["0.32.0"]
        unignored = client.delete(BASE + "/updates/ignored-versions/0.32.0", headers=headers)
        assert unignored.status_code == 204
        missing = client.delete(BASE + "/updates/ignored-versions/9.9.9", headers=headers)
        assert missing.status_code == 404

        backups = client.get(
            BASE + "/updates/backups?mode=docker&sort=createdAtDesc&page=1&pageSize=1",
            headers=headers,
        )
        assert backups.status_code == 200
        assert backups.json()["meta"]["total"] == 1
        assert backups.json()["data"]["items"][0]["ref"] == "b2"
        assert backups.json()["data"]["items"][0]["revision"].startswith("rev_")

        failure_log = client.get(BASE + "/updates/failure-log", headers=headers)
        assert failure_log.status_code == 200
        assert "top-secret" not in failure_log.text
        assert "[REDACTED]" in failure_log.json()["data"]["content"]

        stage_headers = {**headers, "Idempotency-Key": "stage-0.32.0"}
        staged = client.post(BASE + "/updates/0.32.0/actions/stage", headers=stage_headers)
        assert staged.status_code == 202, staged.text
        stage_operation_id = staged.json()["data"]["id"]
        stage_terminal = _poll(client, headers, stage_operation_id)
        assert stage_terminal["status"] == "succeeded"
        plan = stage_terminal["result"]
        assert plan["stagedVersion"] == "0.32.0"
        assert fixture.update_gateway.stage_calls == ["0.32.0"]

        duplicate = client.post(BASE + "/updates/0.32.0/actions/stage", headers=stage_headers)
        assert duplicate.status_code == 202
        assert duplicate.json()["data"]["id"] == stage_operation_id
        assert fixture.update_gateway.stage_calls == ["0.32.0"]

        conflicting = client.post(BASE + "/updates/0.33.0/actions/stage", headers=stage_headers)
        assert conflicting.status_code == 409
        assert conflicting.json()["error"]["code"] == "STATE_CONFLICT"

        activate_headers = {
            **headers,
            "Idempotency-Key": "activate-0.32.0",
            "If-Match": plan["expectedRevision"],
        }
        activated = client.post(
            BASE + "/updates/staged/actions/restart",
            json={"planToken": plan["activationPlanToken"]},
            headers=activate_headers,
        )
        assert activated.status_code == 202, activated.text
        activation_terminal = _poll(client, headers, activated.json()["data"]["id"])
        assert activation_terminal["status"] == "succeeded"
        assert activation_terminal["result"] == {"activated": True}

        replay = client.post(
            BASE + "/updates/staged/actions/restart",
            json={"planToken": plan["activationPlanToken"]},
            headers=activate_headers,
        )
        assert replay.status_code == 409
        assert replay.json()["error"]["code"] == "STATE_CONFLICT"

        staged_again = client.post(
            BASE + "/updates/0.33.0/actions/stage",
            headers={**headers, "Idempotency-Key": "stage-0.33.0"},
        )
        assert staged_again.status_code == 202
        cancelled = client.delete(BASE + "/updates/staged", headers=headers)
        assert cancelled.status_code == 204
        assert fixture.update_gateway.cancel_calls == 1

    assert {record.actor for record in fixture.audit.snapshot()} == {"administrator"}


def test_update_stage_requires_idempotency_and_activation_plan_expires(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        missing_key = client.post(BASE + "/updates/0.32.0/actions/stage", headers=headers)
        assert missing_key.status_code == 422
        assert missing_key.json()["error"]["fields"][0]["path"] == "Idempotency-Key"

        staged = client.post(
            BASE + "/updates/0.32.0/actions/stage",
            headers={**headers, "Idempotency-Key": "stage-expiring"},
        )
        plan = _poll(client, headers, staged.json()["data"]["id"])["result"]
        fixture.controls.updates._clock = lambda: datetime(2026, 1, 2, 1, tzinfo=timezone.utc)
        expired = client.post(
            BASE + "/updates/staged/actions/restart",
            json={"planToken": plan["activationPlanToken"]},
            headers={
                **headers,
                "Idempotency-Key": "activate-expired",
                "If-Match": plan["expectedRevision"],
            },
        )
        assert expired.status_code == 409
        assert expired.json()["error"]["code"] == "STATE_CONFLICT"


def test_image_and_xai_all_operations_no_oauth_secret_and_revision_conflict(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        image = client.get(BASE + "/images/settings", headers=headers)
        assert image.status_code == 200
        image_data = image.json()["data"]
        changed = client.patch(
            BASE + "/images/settings",
            json={
                "cacheEnabled": True,
                "cachePath": "media/images",
                "cacheRetentionDays": 30,
                "cacheMaxBytes": 2048,
            },
            headers={**headers, "If-Match": image_data["revision"]},
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["data"]["cachePath"] == "media/images"
        assert fixture.config.value["images"]["cacheMaxBytes"] == 2048

        stale = client.patch(
            BASE + "/images/settings",
            json={"enabled": False},
            headers={**headers, "If-Match": image_data["revision"]},
        )
        assert stale.status_code == 409

        account_path = BASE + "/images/accounts/openai%3Auser%40example.com"
        account = client.get(account_path, headers=headers)
        assert account.status_code == 200, account.text
        account_data = account.json()["data"]
        assert "token" not in account.text.lower()
        disabled = client.patch(
            account_path,
            json={"enabled": False},
            headers={**headers, "If-Match": account_data["revision"]},
        )
        assert disabled.status_code == 200
        assert disabled.json()["data"]["imageEnabled"] is False
        assert "openai:user@example.com" in fixture.config.value["images"]["disabledAccounts"]
        assert client.get(BASE + "/images/accounts/missing", headers=headers).status_code == 404

        xai = client.get(BASE + "/xai/media-settings", headers=headers)
        assert xai.status_code == 200
        assert xai.json()["data"]["jobTtlSeconds"] == 10800
        xai_changed = client.patch(
            BASE + "/xai/media-settings",
            json={
                "imageModels": ["grok-image-new"],
                "videoModels": [],
                "jobTtlSeconds": 7200,
                "requestTimeoutSeconds": 240,
            },
            headers={**headers, "If-Match": xai.json()["data"]["revision"]},
        )
        assert xai_changed.status_code == 200
        assert xai_changed.json()["data"]["imageModels"] == ["grok-image-new"]
        assert fixture.config.value["xaiOAuth"] == {
            "imageModels": ["grok-image-new"],
            "videoModels": [],
            "videoJobTtlSeconds": 7200,
            "mediaRequestTimeoutSeconds": 240,
        }


def test_image_cache_path_escape_and_xai_model_limits_are_rejected(tmp_path):
    app, _, _ = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        escaped = client.patch(
            BASE + "/images/settings",
            json={"cachePath": "../outside"},
            headers=headers,
        )
        assert escaped.status_code == 422
        assert escaped.json()["error"]["fields"][0]["code"] == "PATH_ESCAPE"

        too_long = client.patch(
            BASE + "/xai/media-settings",
            json={"imageModels": ["x" * 129]},
            headers=headers,
        )
        assert too_long.status_code == 422
        assert too_long.json()["error"]["fields"][0]["path"] == "imageModels[0]"

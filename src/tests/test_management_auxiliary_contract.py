from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.management_auth import AuthMethod
from src.tests.management_auxiliary_support import bearer, build_auxiliary_app, create_session


ROUTES = [
    ("get", "/translation", None, {}),
    ("patch", "/translation", {"enabled": False}, {}),
    ("get", "/translation/cache", None, {}),
    ("delete", "/translation/cache", None, {}),
    ("post", "/translation/actions/test", {"text": "hello"}, {}),
    ("get", "/translation/languages", None, {}),
    ("get", "/status-alerts/settings", None, {}),
    ("patch", "/status-alerts/settings", {"enabled": True}, {}),
    ("get", "/status-alerts/incidents", None, {}),
    ("post", "/status-alerts/actions/refresh", None, {}),
    ("post", "/status-alerts/incidents/inc-1/actions/mute", None, {}),
    ("delete", "/status-alerts/incidents/inc-1/mute", None, {}),
    ("get", "/updates/settings", None, {}),
    ("patch", "/updates/settings", {"enabled": True}, {}),
    ("post", "/updates/actions/check", None, {}),
    ("put", "/updates/ignored-versions/0.32.0", None, {}),
    ("delete", "/updates/ignored-versions/0.32.0", None, {}),
    ("get", "/updates/backups", None, {}),
    ("get", "/updates/failure-log", None, {}),
    ("post", "/updates/0.32.0/actions/stage", None, {"Idempotency-Key": "stage-one"}),
    ("post", "/updates/staged/actions/restart", {"planToken": "not-a-real-plan-token"}, {"Idempotency-Key": "activate-one", "If-Match": "rev_fake"}),
    ("delete", "/updates/staged", None, {}),
    ("get", "/images/settings", None, {}),
    ("patch", "/images/settings", {"enabled": True}, {}),
    ("get", "/images/accounts/openai%3Auser%40example.com", None, {}),
    ("patch", "/images/accounts/openai%3Auser%40example.com", {"enabled": True}, {}),
    ("get", "/xai/media-settings", None, {}),
    ("patch", "/xai/media-settings", {"jobTtlSeconds": 7200}, {}),
]
EXPECTED_OPERATION_IDS = {
    "getTranslationSettings",
    "updateTranslationSettings",
    "getTranslationCacheStats",
    "clearTranslationCache",
    "testTranslation",
    "listTranslationLanguages",
    "getStatusAlertSettings",
    "updateStatusAlertSettings",
    "listStatusIncidents",
    "refreshStatusAlerts",
    "muteStatusIncident",
    "unmuteStatusIncident",
    "getSettings",
    "updateSettings",
    "checkForUpdates",
    "ignoreUpdateVersion",
    "unignoreUpdateVersion",
    "listUpdateBackups",
    "getUpdateFailureLog",
    "stageUpdate",
    "activateStagedUpdate",
    "cancelStagedUpdate",
    "getImageSettings",
    "updateImageSettings",
    "getImageAccountState",
    "updateImageAccountState",
    "getXaiMediaSettings",
    "updateXaiMediaSettings",
}


def _request(client, method, path, *, body, headers):
    return client.request(
        method.upper(),
        "/api/management/v1" + path,
        json=body,
        headers=headers,
    )


@pytest.mark.parametrize("method,path,body,extra_headers", ROUTES)
def test_every_auxiliary_operation_requires_session_and_capability(
    tmp_path, method, path, body, extra_headers,
):
    app, runtime, _ = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        missing = _request(client, method, path, body=body, headers=extra_headers)
        assert missing.status_code == 401, missing.text
        assert missing.json()["error"]["code"] == "SESSION_REQUIRED"

        restricted = runtime.sessions.issue_for_principal(
            subject_id="restricted",
            auth_method=AuthMethod.MANAGEMENT_KEY,
            roles=(),
            capabilities=(),
        )
        headers = {**extra_headers, **bearer(restricted.credential)}
        denied = _request(client, method, path, body=body, headers=headers)
        assert denied.status_code == 403, denied.text
        assert denied.json()["error"]["code"] == "CAPABILITY_DENIED"


@pytest.mark.parametrize(
    "path,body,field",
    [
        ("/translation", {"unknown": True}, "unknown"),
        ("/status-alerts/settings", {"minImpact": "catastrophic"}, "minImpact"),
        ("/updates/settings", {"intervalSeconds": 1}, "intervalSeconds"),
        ("/images/settings", {"cacheRetentionDays": -1}, "cacheRetentionDays"),
        ("/images/accounts/openai%3Auser%40example.com", {"enabled": True, "token": "must-not-appear"}, "token"),
        ("/xai/media-settings", {"jobTtlSeconds": 0}, "jobTtlSeconds"),
    ],
)
def test_typed_patch_validation_has_field_locations(tmp_path, path, body, field):
    app, _, _ = build_auxiliary_app(tmp_path)
    with TestClient(app) as client:
        token = create_session(client)
        response = client.patch("/api/management/v1" + path, json=body, headers=bearer(token))
        assert response.status_code == 422, response.text
        error = response.json()["error"]
        assert error["code"] == "VALIDATION_FAILED"
        assert any(field in item["path"] for item in error["fields"])
        assert "must-not-appear" not in response.text


def test_openapi_has_exact_auxiliary_operations_typed_schemas_and_examples(tmp_path):
    app, _, _ = build_auxiliary_app(tmp_path)
    document = app.openapi()
    operations = {
        operation["operationId"]: operation
        for path, path_item in document["paths"].items()
        if path.startswith("/api/management/v1")
        for method, operation in path_item.items()
        if method in {"get", "patch", "put", "post", "delete"}
        and operation["operationId"] in EXPECTED_OPERATION_IDS
    }
    assert set(operations) == EXPECTED_OPERATION_IDS
    for operation in operations.values():
        assert operation["tags"]
        assert operation["security"] == [{"ManagementSession": []}]
        success = next(
            value for code, value in operation["responses"].items()
            if code.startswith("2")
        )
        if success.get("content"):
            media = success["content"]["application/json"]
            assert "example" in media or "examples" in media
        assert "422" in operation["responses"]
    serialized = repr(document)
    assert "top-secret" not in serialized
    assert document["components"]["schemas"]["ActivateStagedUpdateRequest"]["properties"]["planToken"]["writeOnly"] is True
    for name in (
        "TranslationSettingsData",
        "StatusAlertSettingsData",
        "UpdateSettingsData",
        "ImageSettingsData",
        "ImageAccountStateData",
        "XaiMediaSettingsData",
    ):
        assert name in document["components"]["schemas"]


def test_owned_telegram_menus_call_auxiliary_controls_without_direct_business_io():
    root = Path("src/telegram/menus")
    for name in (
        "translation_menu.py",
        "status_alert_menu.py",
        "update_menu.py",
        "image_menu.py",
        "xai_imagine_menu.py",
    ):
        source = (root / name).read_text(encoding="utf-8")
        assert "management_control.auxiliary" in source
        for direct_call in (
            "config.update(",
            "translation.translate_text_for_test(",
            "status_monitor._process_provider(",
            "update_checker.force_refresh_sync(",
            "updater.stage_update(",
            "images_simple.list_image_accounts(",
            "image_db.get_log(",
        ):
            assert direct_call not in source, (name, direct_call)


def test_auxiliary_routers_have_no_direct_config_runtime_or_updater_imports():
    root = Path("src/management_api/routers")
    files = [
        root / "translation.py",
        root / "status_alerts.py",
        root / "updates.py",
        root / "media_settings.py",
    ]
    forbidden = {
        "src.config",
        "src.translation",
        "src.status_monitor",
        "src.update_checker",
        "src.updater",
        "src.image_db",
        "src.openai.images_simple",
    }
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        assert imports.isdisjoint(forbidden), (path, imports & forbidden)

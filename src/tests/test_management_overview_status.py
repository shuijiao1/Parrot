from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.management_api.dependencies import get_management_context
from src.management_auth import AuthMethod, ManagementPrincipal
from src.management_control import ManagementContext
from src.tests.management_observability_support import build_client


P4_OPERATIONS = {
    "getManagementOverview": ("GET", "/api/management/v1/overview", {}),
    "getRuntimeStatus": ("GET", "/api/management/v1/runtime/status", {}),
    "listBackgroundJobs": ("GET", "/api/management/v1/runtime/background-jobs", {}),
    "listCooldowns": ("GET", "/api/management/v1/runtime/cooldowns", {}),
    "getConcurrencySnapshot": ("GET", "/api/management/v1/runtime/concurrency", {}),
    "getStatsSummary": ("GET", "/api/management/v1/stats/summary", {}),
    "getStatsBreakdown": ("GET", "/api/management/v1/stats/breakdown?dimension=channel", {}),
    "getModelStats": ("GET", "/api/management/v1/stats/models/example-model", {}),
    "listRecentCalls": ("GET", "/api/management/v1/stats/recent-calls", {}),
    "getTelegramStatsPreferences": ("GET", "/api/management/v1/preferences/telegram/stats", {}),
    "updateTelegramStatsPreferences": ("PATCH", "/api/management/v1/preferences/telegram/stats", {"json": {"byChannel": False}}),
    "listRequestLogs": ("GET", "/api/management/v1/logs", {}),
    "getRequestLogFilterOptions": ("GET", "/api/management/v1/logs/filter-options", {}),
    "getRequestLog": ("GET", "/api/management/v1/logs/req-1", {}),
    "getRequestLogBody": ("GET", "/api/management/v1/logs/req-1/body?kind=request", {}),
    "getRequestLogBodyItem": ("GET", "/api/management/v1/logs/req-1/body/items/item_1?kind=request", {}),
    "getRequestLogRawBody": ("GET", "/api/management/v1/logs/req-1/raw-body?kind=request", {}),
    "listMediaLogs": ("GET", "/api/management/v1/media-logs", {}),
    "getMediaLog": ("GET", "/api/management/v1/media-logs/1", {}),
    "listMediaArtifacts": ("GET", "/api/management/v1/media-logs/1/artifacts", {}),
    "downloadMediaArtifact": ("GET", "/api/management/v1/media-logs/1/artifacts/artifact_1_example", {}),
    "getLogRetentionSettings": ("GET", "/api/management/v1/logs/retention", {}),
    "updateLogRetentionSettings": ("PATCH", "/api/management/v1/logs/retention", {"json": {"logStoreBodies": False}}),
    "createLogRetentionPlan": ("POST", "/api/management/v1/logs/retention/plans", {"json": {"days": 30}}),
    "commitLogRetentionPlan": ("POST", "/api/management/v1/logs/retention/plans/plan_example/commit", {"headers": {"If-Match": "rev_plan"}}),
    "cancelLogRetentionPlan": ("DELETE", "/api/management/v1/logs/retention/plans/plan_example", {}),
}


def _request(client, operation, auth=None):
    method, path, options = operation
    options = {key: (dict(value) if isinstance(value, dict) else value) for key, value in options.items()}
    headers = dict(options.pop("headers", {}))
    if auth:
        headers.update(auth)
    return client.request(method, path, headers=headers, **options)


def test_p4_openapi_exact_operations_have_security_tags_schemas_and_examples(tmp_path):
    client, _, _, _ = build_client(tmp_path)
    document = client.get("/openapi.json").json()
    found = {}
    for path, methods in document["paths"].items():
        for method, operation in methods.items():
            if isinstance(operation, dict) and operation.get("operationId") in P4_OPERATIONS:
                found[operation["operationId"]] = operation
    assert set(found) == set(P4_OPERATIONS)
    assert len(found) == 26
    for operation in found.values():
        assert operation["tags"]
        assert operation.get("security") == [{"ManagementSession": []}]
        assert "responses" in operation
        assert any(
            "example" in str(media).lower()
            for response in operation["responses"].values()
            for media in (response.get("content") or {}).values()
        )


@pytest.mark.parametrize("operation_id", P4_OPERATIONS)
def test_each_p4_operation_requires_session_and_capability(operation_id, tmp_path):
    client, _, _controls, _auth = build_client(tmp_path)
    app = client.app
    unauthenticated = _request(client, P4_OPERATIONS[operation_id])
    assert unauthenticated.status_code == 401, (operation_id, unauthenticated.text)
    assert unauthenticated.json()["error"]["code"] == "SESSION_REQUIRED"

    principal = ManagementPrincipal.with_capabilities(
        subject_id="readless", auth_method=AuthMethod.MANAGEMENT_KEY,
        capabilities=(), issued_at=datetime.now(timezone.utc), session_id="limited",
    )
    app.dependency_overrides[get_management_context] = lambda: ManagementContext(
        request_id="request-denied", actor=principal,
    )
    denied = _request(client, P4_OPERATIONS[operation_id])
    app.dependency_overrides.clear()
    assert denied.status_code == 403, (operation_id, denied.text)
    assert denied.json()["error"]["code"] == "CAPABILITY_DENIED"


def test_overview_and_runtime_happy_schema_control_once_and_pagination(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    cases = [
        ("/api/management/v1/overview", controls.status.overview),
        ("/api/management/v1/runtime/status", controls.status.runtime_status),
        ("/api/management/v1/runtime/background-jobs", controls.status.background_jobs),
        ("/api/management/v1/runtime/cooldowns", controls.status.cooldown_page),
        ("/api/management/v1/runtime/concurrency", controls.status.api_concurrency_snapshot),
    ]
    for path, method in cases:
        response = client.get(path, headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["meta"]["requestId"] == "request-p4-test"
        method.assert_called_once()
        assert method.call_args.args[0].actor.subject_id == "administrator"
    assert client.get(
        "/api/management/v1/runtime/cooldowns?pageSize=0", headers=auth,
    ).json()["error"]["fields"][0]["path"] == "pageSize"
    unknown = client.get("/api/management/v1/overview?raw=true", headers=auth)
    assert unknown.status_code == 422
    assert unknown.json()["error"]["fields"][0]["path"] == "raw"

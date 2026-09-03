"""Isolated Management API application and fake controls for P4 tests."""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.management_api import ManagementRuntime, create_management_router, install_management_error_handlers
from src.management_api.routers._observability import ObservabilityControls
from src.management_api.routers.logs import router as logs_router
from src.management_api.routers.media import router as media_router
from src.management_api.routers.overview import router as overview_router
from src.management_api.routers.retention import router as retention_router
from src.management_api.routers.stats import router as stats_router
from src.management_api.routers.status import router as status_router
from src.management_auth import ApprovalService, ManagementStateStore, SessionPolicy, SessionService
from src.management_control import OperationRegistry, OperationStore, StoreAuditSink
from src.management_control.observability import LogBodyPageResult, PageResult


FAKE_KEY = "pmk_" + "O" * 64
# Retention's static GET /logs/retention must precede Logs' /logs/{logId}.
ROUTERS = (overview_router, status_router, stats_router, retention_router, logs_router, media_router)


def _page(items):
    return PageResult(tuple(items), 1, 50, len(items))


def fake_controls() -> ObservabilityControls:
    status = Mock()
    status.overview.return_value = {
        "version": "0.test", "uptimeSeconds": 10,
        "listeners": {"host": "127.0.0.1", "port": 22123},
        "counts": {"channels": 1, "oauthAccounts": 1, "apiKeys": 1, "quotaHot": 0},
        "today": {"total": 2}, "lifetime": {"total": 3}, "activeAlerts": {},
        "revision": "rev_overview",
    }
    status.runtime_status.return_value = {
        "channels": [], "problemChannels": [],
        "fastestByFamily": {"anthropic": [], "openai": []}, "quotaWarnings": [],
        "concurrency": {"channelTotals": {}, "channels": [], "apiKeyTotals": {}, "apiKeys": []},
        "cooldownSummary": {"active": 0, "permanent": 0},
        "affinitySummary": {"server": 0, "client": 0},
        "database": {"status": "healthy"}, "revision": "rev_status",
    }
    status.background_jobs.return_value = _page([{
        "id": "walCheckpoint", "intervalSeconds": None,
        "lastRunAt": None, "nextRunAt": None, "status": "unknown", "error": None,
    }])
    status.cooldown_page.return_value = _page([])
    status.api_concurrency_snapshot.return_value = {
        "channelTotals": {}, "channels": [], "apiKeyTotals": {}, "apiKeys": [],
    }

    stats = Mock()
    stats.summary.return_value = {
        "period": "today", "overall": {"total": 2, "successCount": 2},
        "families": {}, "revision": "rev_stats",
    }
    stats.breakdown.return_value = _page([{"key": "example", "metrics": {"total": 2}}])
    stats.model_stats.return_value = {
        "modelId": "example-model", "period": "today", "metrics": {"total": 2},
        "channels": [], "revision": "rev_model",
    }
    stats.recent_calls.return_value = _page([{
        "request_id": "req-1", "status": "success", "created_at": 1_700_000_000,
        "requested_model": "example-model", "final_channel_key": "api:example", "duration_ms": 10,
    }])
    preferences = {
        "byChannel": True, "byModel": True, "byApiKey": True,
        "cacheMisses": True, "recentCalls": True, "revision": "rev_pref",
    }
    stats.get_preferences.return_value = preferences
    stats.update_preferences.return_value = {**preferences, "byChannel": False, "revision": "rev_pref_2"}

    logs = Mock()
    logs.list_logs.return_value = _page([{
        "id": "req-1", "status": "success", "createdAt": 1_700_000_000,
        "apiKeyName": "client", "requestedModel": "example-model", "finalModel": "example-model",
        "channelId": "api:example", "protocol": "anthropic", "transport": "http",
        "retryCount": 0, "durationMilliseconds": 10, "inputTokens": 1, "outputTokens": 2,
        "costTicks": 3, "error": None, "revision": "rev_log",
    }])
    logs.filter_options.return_value = {
        "apiKeys": [], "models": [], "channels": [],
        "statuses": [{"value": "success", "count": 1}], "protocols": [],
        "revision": "rev_filters",
    }
    log_data = logs.list_logs.return_value.items[0]
    logs.detail.return_value = {
        "id": "req-1", "log": log_data, "stages": [], "attempts": [],
        "localWebRounds": [], "billingAttempts": [], "requestBodyAvailable": True,
        "responseBodyAvailable": True, "requestHeadersAvailable": True, "revision": "rev_detail",
    }
    item = {
        "seq": 1, "kind": "user", "title": "user", "summary": "input",
        "text": "hello", "raw": "hello", "size": 5, "meta": {},
    }
    logs.body_items.return_value = LogBodyPageResult(
        (item,), 1, 50, 1, ({"kind": "user", "count": 1},),
    )
    logs.body_item.return_value = {**item, "id": "item_1"}
    logs.raw_body.return_value = {"logId": "req-1", "kind": "request", "body": {"model": "example"}}

    media = Mock()
    media.list_logs.return_value = _page([{
        "id": "1", "requestId": "req-media", "status": "success", "provider": "openai",
        "model": "gpt-image", "action": "generate", "mediaType": "image", "progress": 100,
        "aspectRatio": "1:1", "resolution": "1024x1024", "durationSeconds": None,
        "durationMilliseconds": 10, "costTicks": 3, "trafficBytes": 5,
        "createdAt": 1_700_000_000, "finishedAt": 1_700_000_001,
        "error": None, "revision": "rev_media",
    }])
    media.detail.return_value = {
        **media.list_logs.return_value.items[0], "accountId": None, "accountLabel": None,
        "upstreamRequestId": None, "upstreamStatus": None, "httpStatus": 200,
        "promptPreview": "safe", "artifactCount": 1, "paths": ["image.png"],
    }
    media.artifacts.return_value = [{
        "id": "artifact_1_example", "fileName": "image.png", "contentType": "image/png",
        "sizeBytes": 3, "mediaType": "image", "expiresAt": None,
    }]
    media.download.return_value = SimpleNamespace(
        filename="image.png", content_type="image/png", size=3, chunks=iter((b"png",)),
    )

    retention = Mock()
    retention.settings.return_value = {
        "mode": "days", "days": 30, "logStoreBodies": True,
        "currentData": {"rows": 4}, "busy": False, "revision": "rev_retention",
    }
    retention.update_settings.return_value = retention.settings.return_value
    plan = {
        "id": "plan_example", "state": "prepared", "days": 30,
        "cutoff": 1_700_000_000, "expiresAt": 1_700_000_600,
        "affectedRows": 1, "affectedFiles": 1, "affectedBytes": 2,
        "scannedRows": 4, "scannedFiles": 1, "scannedBytes": 3,
        "preflightOk": True, "errors": [], "revision": "rev_plan", "operationId": None,
    }
    retention.create_plan.return_value = plan
    retention.cancel_plan.return_value = None

    return ObservabilityControls(status=status, stats=stats, logs=logs, media=media, retention=retention)


def build_client(
    tmp_path,
    *,
    controls_value: ObservabilityControls | None = None,
    inject_controls: bool = True,
):
    store = ManagementStateStore(str(tmp_path / "management.db"), clock=time.time)
    sessions = SessionService(
        store, management_key=FAKE_KEY,
        policy=SessionPolicy(idle_timeout_seconds=3600, absolute_timeout_seconds=7200),
        clock=time.time,
    )
    approvals = ApprovalService(
        store, clock=time.time, ttl_seconds=180,
        admin_ids_provider=lambda: (42,), telegram_configured_provider=lambda: True,
        notifier=SimpleNamespace(send=lambda *_args, **_kwargs: True),
    )
    audit = StoreAuditSink(store)
    operations = OperationStore(audit_sink=audit)
    runtime = ManagementRuntime(
        sessions=sessions, approvals=approvals, operations=operations,
        operation_registry=OperationRegistry(operations), audit_sink=audit,
        state_store=store, allowed_origins=frozenset(), application_version="0.test",
        documentation_url="/docs",
    )
    app = FastAPI()
    app.state.management_runtime = runtime
    if inject_controls:
        app.state.management_observability_controls = controls_value or fake_controls()
        if controls_value is None:
            app.state.management_observability_controls.retention.commit_plan.side_effect = (
                lambda context, plan_id, *, expected_revision, operations:
                operations.create(context, kind="logs.retention.commit", cancellable=False)
            )
    app.include_router(create_management_router(ROUTERS))
    install_management_error_handlers(app)
    client = TestClient(app)
    response = client.post(
        "/api/management/v1/auth/sessions",
        json={"grantType": "managementKey", "managementKey": FAKE_KEY},
    )
    assert response.status_code == 201, response.text
    credential = response.json()["data"]["credential"]
    return client, runtime, getattr(app.state, "management_observability_controls", None), {
        "Authorization": f"Bearer {credential}", "X-Request-Id": "request-p4-test",
    }

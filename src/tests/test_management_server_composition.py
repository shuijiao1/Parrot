from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

import server
from src.management_api import ManagementRuntime


EXPECTED_OPERATIONS = {
    "createManagementSession",
    "getCurrentManagementSession",
    "revokeCurrentManagementSession",
    "createTelegramApproval",
    "getTelegramApproval",
    "getManagementMetadata",
    "getManagementCapabilities",
    "getManagementOperation",
    "getTelegramApproval",
    "cancelManagementOperation",
}


def settings(tmp_path):
    return {
        "managementKey": "pmk_" + "S" * 64,
        "stateDbPath": str(tmp_path / "management-composition.db"),
        "allowedOrigins": (),
        "sessionIdleTimeoutSeconds": 3 * 24 * 60 * 60,
        "sessionAbsoluteTimeoutSeconds": 30 * 24 * 60 * 60,
        "sessionTouchIntervalSeconds": 300,
        "telegramApprovalTtlSeconds": 180,
        "authRateLimitWindowSeconds": 60,
        "authRateLimitPerSource": 5,
        "authRateLimitGlobal": 30,
        "maxOperations": 100,
        "maxAuditRecords": 100,
    }


def test_server_mounts_the_exact_p0_router_and_preserves_lifecycle_order():
    document = server.app.openapi()
    actual = {
        operation["operationId"]
        for path, path_item in document["paths"].items()
        if path.startswith("/api/management/v1")
        for method, operation in path_item.items()
        if method in {"get", "post", "delete", "put", "patch"}
    }
    assert actual == EXPECTED_OPERATIONS

    source = Path("server.py").read_text()
    assert source.index("state_db.init()") < source.index("network.init()")
    assert source.index("network.init()") < source.index("log_db.init()")
    assert source.index("log_db.init()") < source.index("image_db.init()")
    assert source.index("image_db.init()") < source.index("translation.init()")
    assert source.index("translation.init()") < source.index("_initialize_management_runtime(app)")
    assert source.index("provider_usage.schedule_startup_refresh()") < source.index("tgbot.start()")
    stop = source.index("tgbot.stop()")
    assert stop < source.index("_close_management_runtime(app)", stop)
    assert source.index("_close_management_runtime(app)", stop) < source.index(
        "await provider_usage.stop()", stop,
    )


def test_management_initialization_and_shutdown_are_isolated(tmp_path, monkeypatch, capsys):
    app = FastAPI()
    values = settings(tmp_path)
    monkeypatch.setattr(server.config, "management_settings", lambda: values)
    runtime = server._initialize_management_runtime(app)
    assert isinstance(runtime, ManagementRuntime)
    assert app.state.management_runtime is runtime
    assert (tmp_path / "management-composition.db").exists()
    output = capsys.readouterr().out
    assert values["managementKey"] not in output
    server._close_management_runtime(app)
    assert app.state.management_runtime is None
    assert server.tgbot._management_approval_handler is None


def test_server_metadata_links_to_served_fastapi_documentation(
    tmp_path, monkeypatch,
):
    values = settings(tmp_path)
    monkeypatch.setattr(server.config, "management_settings", lambda: values)
    holder = FastAPI()
    runtime = server._initialize_management_runtime(holder)
    assert isinstance(runtime, ManagementRuntime)
    issued = runtime.sessions.create_from_management_key(
        values["managementKey"],
        source="composition-test",
        request_id="documentation-test",
    )

    original_runtime = server.app.state.management_runtime
    server.drain.reset_for_tests()
    server.app.state.management_runtime = runtime
    try:
        client = TestClient(server.app)
        metadata = client.get(
            "/api/management/v1/meta",
            headers={"Authorization": f"Bearer {issued.credential}"},
        )
        assert metadata.status_code == 200
        documentation_url = metadata.json()["data"]["documentationUrl"]
        assert documentation_url == "/docs"
        documentation = client.get(documentation_url)
        assert documentation.status_code == 200
        assert "/openapi.json" in documentation.text
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        assert "/api/management/v1/meta" in openapi.json()["paths"]
    finally:
        server.app.state.management_runtime = original_runtime
        server._close_management_runtime(holder)
        server.drain.reset_for_tests()


def test_management_initialization_failure_stays_fail_closed_and_inference_health_works(
    monkeypatch,
):
    app = FastAPI()

    def fail_settings():
        raise ValueError("fake-sensitive-management-config-value")

    monkeypatch.setattr(server.config, "management_settings", fail_settings)
    assert server._initialize_management_runtime(app) is None
    assert app.state.management_runtime is None

    original = server.app.state.management_runtime
    server.drain.reset_for_tests()
    server.app.state.management_runtime = None
    try:
        client = TestClient(server.app)
        management = client.get("/api/management/v1/meta")
        assert management.status_code == 503
        assert management.json()["error"]["code"] == "SERVICE_NOT_READY"
        inference_health = client.get("/health")
        assert inference_health.status_code == 200
        assert "status" in inference_health.json()
    finally:
        server.app.state.management_runtime = original
        server.drain.reset_for_tests()

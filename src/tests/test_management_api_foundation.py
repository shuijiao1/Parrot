from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from src.management_api import (
    ManagementOriginMiddleware,
    ManagementRuntime,
    create_management_router,
    install_management_error_handlers,
)
from src.management_auth import (
    ApprovalService,
    AuthMethod,
    ManagementStateStore,
    SessionPolicy,
    SessionService,
)
from src.management_control import (
    ManagementContext,
    OperationRegistry,
    OperationStore,
    StoreAuditSink,
)


FAKE_KEY = "pmk_" + "M" * 64
EXPECTED_OPERATIONS = {
    "createManagementSession",
    "getCurrentManagementSession",
    "revokeCurrentManagementSession",
    "createTelegramApproval",
    "getTelegramApproval",
    "getManagementMetadata",
    "getManagementCapabilities",
    "getManagementOperation",
    "cancelManagementOperation",
}


class FakeNotifier:
    def __init__(self) -> None:
        self.notifications = []

    def send(self, admin_ids, notification):
        self.notifications.append((admin_ids, notification))
        return True


def build_app(tmp_path, *, allowed_origins=("https://admin.example.test",)):
    clock = time.time
    store = ManagementStateStore(
        str(tmp_path / "management-api.db"),
        clock=clock,
    )
    sessions = SessionService(
        store,
        management_key=FAKE_KEY,
        policy=SessionPolicy(
            idle_timeout_seconds=3 * 24 * 60 * 60,
            absolute_timeout_seconds=30 * 24 * 60 * 60,
            touch_interval_seconds=300,
        ),
        clock=clock,
    )
    notifier = FakeNotifier()
    approvals = ApprovalService(
        store,
        clock=clock,
        ttl_seconds=180,
        admin_ids_provider=lambda: (42,),
        telegram_configured_provider=lambda: True,
        notifier=notifier,
    )
    audit_sink = StoreAuditSink(store)
    operations = OperationStore(audit_sink=audit_sink)
    runtime = ManagementRuntime(
        sessions=sessions,
        approvals=approvals,
        operations=operations,
        operation_registry=OperationRegistry(operations),
        audit_sink=audit_sink,
        state_store=store,
        allowed_origins=frozenset(allowed_origins),
        application_version="0.test",
        documentation_url="https://docs.example.test/management-v1",
    )
    app = FastAPI()
    app.state.management_runtime = runtime
    app.include_router(create_management_router())
    install_management_error_handlers(app)
    # Deliberately reproduce the inference API's broad CORS, then wrap it with
    # the path-scoped management policy.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(ManagementOriginMiddleware)
    return app, runtime, notifier


def create_session(client: TestClient, *, key: str = FAKE_KEY) -> str:
    response = client.post(
        "/api/management/v1/auth/sessions",
        json={"grantType": "managementKey", "managementKey": key},
        headers={"X-Request-Id": "req-create-session"},
    )
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"] == "req-create-session"
    return response.json()["data"]["credential"]


def bearer(credential: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential}"}


def test_openapi_has_exact_p0_operation_ids_typed_schemas_and_security(tmp_path):
    app, _, _ = build_app(tmp_path)
    document = app.openapi()
    operations = {}
    for path, item in document["paths"].items():
        if not path.startswith("/api/management/v1"):
            continue
        for method, operation in item.items():
            if method.lower() in {"get", "post", "delete", "patch", "put"}:
                operations[operation["operationId"]] = (method, path, operation)
    manifest = Path("src/tests/fixtures/management_api/v1-operation-ids.txt")
    manifested = {line for line in manifest.read_text().splitlines() if line}
    assert manifested == EXPECTED_OPERATIONS
    assert set(operations) == manifested
    assert len(operations) == 9
    for operation_id, (_, _, operation) in operations.items():
        assert operation["tags"]
        assert "responses" in operation
        if operation_id not in {"createManagementSession", "createTelegramApproval", "getTelegramApproval"}:
            assert operation.get("security") == [{"ManagementSession": []}]

    schemas = document["components"]["schemas"]
    serialized = repr(schemas)
    assert "SessionCredentialData" in schemas
    assert schemas["ManagementKeyGrant"]["properties"]["managementKey"]["writeOnly"] is True
    assert schemas["TelegramApprovalGrant"]["properties"]["exchangeSecret"]["writeOnly"] is True
    assert schemas["SessionCredentialData"]["properties"]["credential"]["writeOnly"] is True
    assert "additionalProperties': False" in serialized
    assert "pms_" not in serialized and "pmk_" not in serialized and "max_" not in serialized


def test_management_key_grant_bearer_session_revoke_and_replay(tmp_path):
    app, _, _ = build_app(tmp_path)
    with TestClient(app) as client:
        credential = create_session(client)
        current = client.get("/api/management/v1/auth/session", headers=bearer(credential))
        assert current.status_code == 200
        data = current.json()["data"]
        assert data["authMethod"] == "managementKey"
        assert data["subjectId"] == "administrator"
        assert "management.read" in data["capabilities"]
        assert current.headers["cache-control"] == "no-store"

        meta = client.get("/api/management/v1/meta", headers=bearer(credential))
        assert meta.status_code == 200
        assert meta.json()["data"]["apiVersion"] == "v1"
        assert meta.json()["data"]["applicationVersion"] == "0.test"

        revoked = client.delete("/api/management/v1/auth/session", headers=bearer(credential))
        assert revoked.status_code == 204 and revoked.content == b""
        assert revoked.headers["cache-control"] == "no-store"
        replay = client.get("/api/management/v1/meta", headers=bearer(credential))
        assert replay.status_code == 401
        assert replay.json()["error"]["code"] == "SESSION_REQUIRED"
        assert credential not in replay.text


def test_auth_failure_validation_envelope_unknown_fields_and_capability(tmp_path):
    app, runtime, _ = build_app(tmp_path)
    with TestClient(app) as client:
        bad_key = client.post(
            "/api/management/v1/auth/sessions",
            json={"grantType": "managementKey", "managementKey": "not-the-key"},
        )
        assert bad_key.status_code == 401
        assert bad_key.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        assert "not-the-key" not in bad_key.text

        unknown = client.post(
            "/api/management/v1/auth/sessions",
            json={
                "grantType": "managementKey",
                "managementKey": FAKE_KEY,
                "unexpected": True,
            },
        )
        assert unknown.status_code == 422
        body = unknown.json()["error"]
        assert body["code"] == "VALIDATION_FAILED"
        assert body["fields"] and "unexpected" in body["fields"][0]["path"]

        restricted = runtime.sessions.issue_for_principal(
            subject_id="restricted",
            auth_method=AuthMethod.MANAGEMENT_KEY,
            roles=(),
            capabilities=(),
        )
        own_session = client.get(
            "/api/management/v1/auth/session", headers=bearer(restricted.credential),
        )
        assert own_session.status_code == 200
        denied = client.get("/api/management/v1/meta", headers=bearer(restricted.credential))
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "CAPABILITY_DENIED"


def test_telegram_grant_polling_binding_consumption_and_no_store(tmp_path):
    app, runtime, notifier = build_app(tmp_path)
    with TestClient(app) as client:
        created = client.post(
            "/api/management/v1/auth/telegram-approvals",
            json={"clientName": "test-browser", "deviceSummary": "fake-device"},
        )
        assert created.status_code == 201
        assert created.headers["cache-control"] == "no-store"
        challenge = created.json()["data"]
        assert challenge["pollAfterSeconds"] >= 1
        assert notifier.notifications
        notification = notifier.notifications[-1][1]
        assert challenge["exchangeSecret"] not in repr(notification)

        wrong = client.get(
            f"/api/management/v1/auth/telegram-approvals/{challenge['approvalId']}",
            headers={"Authorization": "Approval wrong-browser"},
        )
        assert wrong.status_code == 401
        runtime.approvals.decide(
            challenge["approvalId"], telegram_user_id=42, approved=True,
        )
        polled = client.get(
            f"/api/management/v1/auth/telegram-approvals/{challenge['approvalId']}",
            headers={"Authorization": f"Approval {challenge['exchangeSecret']}"},
        )
        assert polled.status_code == 200
        assert polled.json()["data"]["status"] == "approved"
        assert "credential" not in polled.text

        exchanged = client.post(
            "/api/management/v1/auth/sessions",
            json={
                "grantType": "telegramApproval",
                "approvalId": challenge["approvalId"],
                "exchangeSecret": challenge["exchangeSecret"],
            },
        )
        assert exchanged.status_code == 201
        assert exchanged.json()["data"]["session"]["authMethod"] == "telegramApproval"
        replay = client.post(
            "/api/management/v1/auth/sessions",
            json={
                "grantType": "telegramApproval",
                "approvalId": challenge["approvalId"],
                "exchangeSecret": challenge["exchangeSecret"],
            },
        )
        assert replay.status_code == 401
        assert replay.json()["error"]["code"] == "AUTHENTICATION_FAILED"


def test_operation_auth_session_visibility_and_cancel(tmp_path):
    app, runtime, _ = build_app(tmp_path)
    with TestClient(app) as client:
        owner_token = create_session(client)
        other_token = create_session(client)
        owner_principal = runtime.sessions.verify(owner_token).principal
        operation = runtime.operations.create(
            ManagementContext(request_id="op-create", actor=owner_principal),
            kind="test.pending",
            cancellable=True,
        )
        missing_auth = client.get(f"/api/management/v1/operations/{operation.id}")
        assert missing_auth.status_code == 401
        hidden = client.get(
            f"/api/management/v1/operations/{operation.id}",
            headers=bearer(other_token),
        )
        assert hidden.status_code == 404
        assert hidden.json()["error"]["code"] == "OPERATION_NOT_FOUND"
        visible = client.get(
            f"/api/management/v1/operations/{operation.id}",
            headers=bearer(owner_token),
        )
        assert visible.status_code == 200
        assert visible.json()["data"]["status"] == "queued"
        cancelled = client.delete(
            f"/api/management/v1/operations/{operation.id}",
            headers=bearer(owner_token),
        )
        assert cancelled.status_code == 204
        final = client.get(
            f"/api/management/v1/operations/{operation.id}",
            headers=bearer(owner_token),
        )
        assert final.json()["data"]["status"] == "cancelled"


def test_management_origin_policy_overrides_broad_cors_but_cli_bearer_works(tmp_path):
    app, _, _ = build_app(tmp_path)
    with TestClient(app) as client:
        denied = client.post(
            "/api/management/v1/auth/sessions",
            json={"grantType": "managementKey", "managementKey": FAKE_KEY},
            headers={"Origin": "https://evil.example.test"},
        )
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "ORIGIN_DENIED"
        assert "access-control-allow-origin" not in denied.headers

        allowed = client.post(
            "/api/management/v1/auth/sessions",
            json={"grantType": "managementKey", "managementKey": FAKE_KEY},
            headers={"Origin": "https://admin.example.test"},
        )
        assert allowed.status_code == 201
        assert allowed.headers["access-control-allow-origin"] == "https://admin.example.test"
        assert allowed.headers["access-control-allow-origin"] != "*"

        preflight = client.options(
            "/api/management/v1/meta",
            headers={
                "Origin": "https://admin.example.test",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert preflight.status_code == 204
        assert preflight.headers["access-control-allow-origin"] == "https://admin.example.test"

        cli_token = create_session(client)
        cli = client.get("/api/management/v1/meta", headers=bearer(cli_token))
        assert cli.status_code == 200
        assert "access-control-allow-origin" not in cli.headers


def test_router_accepts_explicit_domain_registration_without_common_type_changes(tmp_path):
    extra = APIRouter()

    @extra.get("/domain-probe", operation_id="getDomainProbe", tags=["probe"])
    async def probe():
        return {"ok": True}

    app = FastAPI()
    app.include_router(create_management_router([extra]))
    assert app.openapi()["paths"]["/api/management/v1/domain-probe"]["get"]["operationId"] == "getDomainProbe"

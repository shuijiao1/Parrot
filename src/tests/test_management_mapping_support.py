"""Shared authorized test harness for the P5 domain routers.

The filename remains inside the mapping-owned test prefix; other P5 tests import
its fixture explicitly rather than modifying global conftest/P0 fixtures.
"""

from __future__ import annotations

import ast
import copy
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src import config
from src.management_api import ManagementRuntime, create_management_router, install_management_error_handlers
from src.management_api.routers.load_balancing import router as load_balancing_router
from src.management_api.routers.mapping import router as mapping_router
from src.management_api.routers.model_metadata import router as model_metadata_router
from src.management_api.routers.proxy import router as proxy_router
from src.management_auth import (
    ApprovalService,
    AuthMethod,
    Capability,
    ManagementStateStore,
    SessionPolicy,
    SessionService,
)
from src.management_control import OperationRegistry, OperationStore, StoreAuditSink


FAKE_KEY = "pmk_" + "P" * 64
OWNED_OPERATION_IDS = {
    "listModelMappings", "putModelMapping", "deleteModelMapping",
    "getIngressDefaultModel", "putIngressDefaultModel", "deleteIngressDefaultModel",
    "listModelInventory", "listModelMetadata", "getModelMetadata",
    "putModelMetadataBinding", "deleteModelMetadataBinding", "syncModelMetadata",
    "searchModelCatalog", "getCompressionModel", "putCompressionModel",
    "deleteCompressionModel", "getLoadBalancing", "updateLoadBalancingMode",
    "getChannelOrder", "replaceChannelOrder", "getModelChannelOrder",
    "replaceModelChannelOrder", "deleteModelChannelOrder",
    "bulkReplaceModelChannelOrders", "clearAllAffinity", "clearFamilyAffinity",
    "listProxies", "createProxies", "getProxy", "updateProxy", "deleteProxy",
    "testProxy", "listProxyGroups", "createProxyGroups", "getProxyGroup",
    "updateProxyGroup", "deleteProxyGroup", "testProxyGroup", "getProxyRouting",
    "updateProxyRouting",
}
OWNED_TAGS = {
    "management-model-mapping",
    "management-model-metadata",
    "management-load-balancing",
    "management-proxy",
}


class FakeNotifier:
    def send(self, *_args, **_kwargs):
        return True


@pytest.fixture
def domain_client(tmp_path):
    config.update(
        lambda current: (current.clear(), current.update(copy.deepcopy(config.DEFAULT_CONFIG)))
    )
    store = ManagementStateStore(str(tmp_path / "management-p5.db"), clock=time.time)
    sessions = SessionService(
        store,
        management_key=FAKE_KEY,
        policy=SessionPolicy(
            idle_timeout_seconds=3_600,
            absolute_timeout_seconds=7_200,
            touch_interval_seconds=60,
        ),
        clock=time.time,
    )
    approvals = ApprovalService(
        store,
        clock=time.time,
        ttl_seconds=180,
        admin_ids_provider=lambda: (42,),
        telegram_configured_provider=lambda: True,
        notifier=FakeNotifier(),
    )
    audit = StoreAuditSink(store)
    operations = OperationStore(audit_sink=audit)
    runtime = ManagementRuntime(
        sessions=sessions,
        approvals=approvals,
        operations=operations,
        operation_registry=OperationRegistry(operations),
        audit_sink=audit,
        state_store=store,
        allowed_origins=frozenset(),
        application_version="0.p5-test",
        documentation_url="https://docs.example.test/management-v1",
    )
    app = FastAPI()
    app.state.management_runtime = runtime
    app.include_router(create_management_router((
        mapping_router,
        model_metadata_router,
        load_balancing_router,
        proxy_router,
    )))
    install_management_error_handlers(app)
    client = TestClient(app)
    response = client.post(
        "/api/management/v1/auth/sessions",
        json={"grantType": "managementKey", "managementKey": FAKE_KEY},
    )
    assert response.status_code == 201
    credential = response.json()["data"]["credential"]
    limited = sessions.issue_for_principal(
        subject_id="read-only",
        auth_method=AuthMethod.MANAGEMENT_KEY,
        roles=(),
        capabilities=(Capability.READ,),
    )
    denied = sessions.issue_for_principal(
        subject_id="no-capabilities",
        auth_method=AuthMethod.MANAGEMENT_KEY,
        roles=(),
        capabilities=(),
    )
    try:
        yield client, runtime, {
            "Authorization": f"Bearer {credential}",
        }, {
            "Authorization": f"Bearer {limited.credential}",
        }, {
            "Authorization": f"Bearer {denied.credential}",
        }
    finally:
        runtime.close()


def operation_map(client: TestClient) -> dict[str, dict]:
    document = client.get("/openapi.json").json()
    return {
        operation["operationId"]: operation
        for path, path_item in document["paths"].items()
        if path.startswith("/api/management/v1")
        for method, operation in path_item.items()
        if method in {"get", "put", "post", "patch", "delete"}
    }


def test_openapi_matches_owned_operation_manifest(domain_client):
    client, *_ = domain_client
    owned = {
        operation_id
        for operation_id, operation in operation_map(client).items()
        if set(operation.get("tags") or ()) & OWNED_TAGS
    }
    assert owned == OWNED_OPERATION_IDS
    assert len(owned) == 40


def test_p5_router_operations_each_call_control_once_with_authorized_context():
    root = Path(__file__).resolve().parents[2]
    operations = []
    for relative in (
        "src/management_api/routers/mapping.py",
        "src/management_api/routers/model_metadata.py",
        "src/management_api/routers/load_balancing.py",
        "src/management_api/routers/proxy.py",
    ):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_operation = any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "router"
                for decorator in node.decorator_list
            )
            if not is_operation:
                continue
            control_calls = [
                call for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "control"
            ]
            assert len(control_calls) == 1, (relative, node.name, control_calls)
            assert control_calls[0].args
            first_argument = control_calls[0].args[0]
            assert isinstance(first_argument, ast.Name)
            assert first_argument.id == "context", (relative, node.name)
            operations.append((relative, node.name))
    assert len(operations) == 40


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/management/v1/model-mappings"),
        ("delete", "/api/management/v1/model-mappings/example"),
        ("get", "/api/management/v1/ingress-default-models/anthropic"),
        ("delete", "/api/management/v1/ingress-default-models/anthropic"),
        ("get", "/api/management/v1/compression-model"),
        ("delete", "/api/management/v1/compression-model"),
        ("get", "/api/management/v1/models/inventory"),
        ("get", "/api/management/v1/model-metadata"),
        ("get", "/api/management/v1/model-metadata/example"),
        ("delete", "/api/management/v1/model-metadata/example/binding"),
        ("get", "/api/management/v1/model-catalog"),
        ("get", "/api/management/v1/load-balancing"),
        ("get", "/api/management/v1/load-balancing/channel-order"),
        ("get", "/api/management/v1/load-balancing/model-orders/example"),
        ("delete", "/api/management/v1/load-balancing/model-orders/example"),
        ("get", "/api/management/v1/proxies"),
        ("get", "/api/management/v1/proxies/example"),
        ("delete", "/api/management/v1/proxies/example"),
        ("get", "/api/management/v1/proxy-groups"),
        ("get", "/api/management/v1/proxy-groups/example"),
        ("delete", "/api/management/v1/proxy-groups/example"),
        ("get", "/api/management/v1/proxy-routing"),
    ],
)
def test_every_p5_get_and_delete_rejects_unknown_query_parameters(
    domain_client, method, path,
):
    client, _runtime, admin, *_ = domain_client
    response = client.request(method, f"{path}?undeclared=1", headers=admin)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_FAILED"
    assert response.json()["error"]["fields"] == [{
        "path": "undeclared",
        "code": "UNKNOWN_QUERY_PARAMETER",
        "message": "query parameter 'undeclared' is not supported",
    }]

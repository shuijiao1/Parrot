"""Shared authorized test harness for the P5 domain routers.

The filename remains inside the mapping-owned test prefix; other P5 tests import
its fixture explicitly rather than modifying global conftest/P0 fixtures.
"""

from __future__ import annotations

import copy
import time

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

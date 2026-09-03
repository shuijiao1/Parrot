from __future__ import annotations

from dataclasses import dataclass

import pytest

from src import affinity
from src.channel import registry
from src.tests.test_management_mapping_support import domain_client, operation_map


LB_OPERATIONS = {
    "getLoadBalancing", "updateLoadBalancingMode", "getChannelOrder",
    "replaceChannelOrder", "getModelChannelOrder", "replaceModelChannelOrder",
    "deleteModelChannelOrder", "bulkReplaceModelChannelOrders",
    "clearAllAffinity", "clearFamilyAffinity",
}


@dataclass
class FakeChannel:
    key: str
    models: tuple[str, ...]
    type: str = "api"
    display_name: str = "Fake"
    enabled: bool = True
    disabled_reason: str | None = None
    protocol: str = "anthropic"

    def list_client_models(self):
        return list(self.models)

    def supports_model(self, model):
        return model if model in self.models else None


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("get", "/api/management/v1/load-balancing", None),
        ("patch", "/api/management/v1/load-balancing", {"mode": "smart"}),
        ("get", "/api/management/v1/load-balancing/channel-order", None),
        ("put", "/api/management/v1/load-balancing/channel-order", {"order": []}),
        ("get", "/api/management/v1/load-balancing/model-orders/model", None),
        ("put", "/api/management/v1/load-balancing/model-orders/model", {"order": []}),
        ("delete", "/api/management/v1/load-balancing/model-orders/model", None),
        ("put", "/api/management/v1/load-balancing/model-orders", {"modelIds": ["model"], "order": []}),
        ("post", "/api/management/v1/affinity/actions/clear", None),
        ("post", "/api/management/v1/affinity/families/anthropic/actions/clear", None),
    ],
)
def test_lb_operations_require_session_and_capability(domain_client, method, path, body):
    client, _runtime, _admin, read_only, denied = domain_client
    assert client.request(method, path, json=body).status_code == 401
    forbidden = denied if method == "get" else read_only
    response = client.request(method, path, headers=forbidden, json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CAPABILITY_DENIED"


def test_lb_openapi_is_typed_and_has_examples(domain_client):
    client, *_ = domain_client
    operations = operation_map(client)
    assert LB_OPERATIONS <= set(operations)
    for operation_id in LB_OPERATIONS:
        operation = operations[operation_id]
        assert operation["tags"]
        assert operation.get("security") == [{"ManagementSession": []}]
        success = next(value for code, value in operation["responses"].items() if code.startswith("2"))
        if operation_id == "deleteModelChannelOrder":
            assert success["description"]
        else:
            assert success["content"]["application/json"]["example"]


def test_mode_and_complete_channel_order_revision(domain_client, monkeypatch):
    client, runtime, admin, *_ = domain_client
    channels = [FakeChannel("api:a", ("m1", "m2")), FakeChannel("api:b", ("m1",))]
    monkeypatch.setattr(registry, "all_channels", lambda: channels)
    monkeypatch.setattr(registry, "get_channel", lambda key: next((c for c in channels if c.key == key), None))

    current = client.get("/api/management/v1/load-balancing", headers=admin)
    assert current.status_code == 200
    changed = client.patch(
        "/api/management/v1/load-balancing",
        headers={**admin, "If-Match": current.json()["data"]["revision"]},
        json={"mode": "priority"},
    )
    assert changed.status_code == 200
    assert changed.json()["data"]["mode"] == "priority"

    order = client.get("/api/management/v1/load-balancing/channel-order", headers=admin)
    revision = order.json()["data"]["revision"]
    assert order.json()["data"]["order"] == ["api:a", "api:b"]
    missing_confirmation = client.put(
        "/api/management/v1/load-balancing/channel-order",
        headers=admin,
        json={"order": ["api:b", "api:a"]},
    )
    assert missing_confirmation.status_code == 400
    assert missing_confirmation.json()["error"]["code"] == "CONFIRMATION_REQUIRED"
    invalid = client.put(
        "/api/management/v1/load-balancing/channel-order",
        headers={**admin, "If-Match": revision},
        json={"order": ["api:a"]},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["fields"][0]["path"] == "order"
    replaced = client.put(
        "/api/management/v1/load-balancing/channel-order",
        headers={**admin, "If-Match": revision},
        json={"order": ["api:b", "api:a"]},
    )
    assert replaced.status_code == 200
    assert replaced.json()["data"]["order"] == ["api:b", "api:a"]
    assert any(
        row["actor"] == "administrator" and row["action"] == "load_balancing.channel_order.replace"
        for row in runtime.state_store.audit_snapshot()
    )


def test_model_orders_single_bulk_delete_and_stale(domain_client, monkeypatch):
    client, _runtime, admin, *_ = domain_client
    channels = [
        FakeChannel("api:a", ("m1", "m2")),
        FakeChannel("api:b", ("m1",)),
        FakeChannel("api:c", ("m2",)),
    ]
    monkeypatch.setattr(registry, "all_channels", lambda: channels)
    monkeypatch.setattr(registry, "get_channel", lambda key: next((c for c in channels if c.key == key), None))

    detail = client.get("/api/management/v1/load-balancing/model-orders/m1", headers=admin)
    assert detail.status_code == 200
    revision = detail.json()["data"]["revision"]
    put = client.put(
        "/api/management/v1/load-balancing/model-orders/m1",
        headers={**admin, "If-Match": revision},
        json={"order": ["api:b", "api:a"]},
    )
    assert put.status_code == 200
    assert put.json()["data"]["source"] == "modelOverride"
    stale = client.put(
        "/api/management/v1/load-balancing/model-orders/m1",
        headers={**admin, "If-Match": revision},
        json={"order": ["api:a", "api:b"]},
    )
    assert stale.status_code == 409

    current = client.get("/api/management/v1/load-balancing/model-orders/m2", headers=admin)
    bulk = client.put(
        "/api/management/v1/load-balancing/model-orders",
        headers={**admin, "If-Match": current.json()["data"]["revision"]},
        json={"modelIds": ["m1", "m2"], "order": ["api:b", "api:a", "api:c"]},
    )
    assert bulk.status_code == 200, bulk.text
    values = {item["modelId"]: item["order"] for item in bulk.json()["data"]["orders"]}
    assert values == {"m1": ["api:b", "api:a"], "m2": ["api:a", "api:c"]}
    deleted = client.delete(
        "/api/management/v1/load-balancing/model-orders/m1",
        headers={**admin, "If-Match": bulk.json()["data"]["revision"]},
    )
    assert deleted.status_code == 204
    assert client.get(
        "/api/management/v1/load-balancing/model-orders/missing", headers=admin
    ).status_code == 404


def test_affinity_clear_calls_both_runtime_owners(domain_client, monkeypatch):
    client, _runtime, admin, *_ = domain_client
    calls = []
    monkeypatch.setattr(affinity, "count", lambda: 3)
    monkeypatch.setattr(affinity, "client_count", lambda: 2)
    monkeypatch.setattr(affinity, "delete_all", lambda: calls.append("fingerprint-all"))
    monkeypatch.setattr(affinity, "client_delete_all", lambda: calls.append("client-all"))
    monkeypatch.setattr(affinity, "delete_by_protocol", lambda family: calls.append(("fingerprint", family)) or 4)
    monkeypatch.setattr(affinity, "client_delete_by_protocol", lambda family: calls.append(("client", family)) or 5)

    cleared = client.post("/api/management/v1/affinity/actions/clear", headers=admin)
    assert cleared.status_code == 200
    assert cleared.json()["data"]["fingerprintCount"] == 3
    assert calls[:2] == ["fingerprint-all", "client-all"]
    family = client.post(
        "/api/management/v1/affinity/families/openai/actions/clear", headers=admin
    )
    assert family.status_code == 200
    assert family.json()["data"]["clientCount"] == 5
    assert calls[-2:] == [("fingerprint", "openai"), ("client", "openai")]


def test_lb_unknown_fields_and_enum_have_422_fields(domain_client):
    client, _runtime, admin, *_ = domain_client
    response = client.patch(
        "/api/management/v1/load-balancing",
        headers=admin,
        json={"mode": "random", "unknown": True},
    )
    assert response.status_code == 422
    assert response.json()["error"]["fields"]

from __future__ import annotations

import time

import pytest

from src import model_metadata, model_pricing
from src.tests.test_management_mapping_support import domain_client, operation_map


METADATA_OPERATIONS = {
    "listModelInventory", "listModelMetadata", "getModelMetadata",
    "putModelMetadataBinding", "deleteModelMetadataBinding",
    "syncModelMetadata", "searchModelCatalog",
}


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("get", "/api/management/v1/models/inventory", None),
        ("get", "/api/management/v1/model-metadata", None),
        ("get", "/api/management/v1/model-metadata/example", None),
        ("put", "/api/management/v1/model-metadata/example/binding", {"scope": "global", "targetModelId": "p/m", "providerId": "p"}),
        ("delete", "/api/management/v1/model-metadata/example/binding", None),
        ("post", "/api/management/v1/model-metadata/actions/sync", {"scope": "full"}),
        ("get", "/api/management/v1/model-catalog", None),
    ],
)
def test_metadata_operations_require_session_and_capability(domain_client, method, path, body):
    client, _runtime, _admin, read_only, denied = domain_client
    assert client.request(method, path, json=body).status_code == 401
    forbidden = denied if method == "get" else read_only
    response = client.request(method, path, headers=forbidden, json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CAPABILITY_DENIED"


def test_metadata_openapi_is_typed_and_has_examples(domain_client):
    client, *_ = domain_client
    operations = operation_map(client)
    assert METADATA_OPERATIONS <= set(operations)
    for operation_id in METADATA_OPERATIONS:
        operation = operations[operation_id]
        assert operation["tags"]
        assert operation.get("security") == [{"ManagementSession": []}]
        success = next(value for code, value in operation["responses"].items() if code.startswith("2"))
        if operation_id == "deleteModelMetadataBinding":
            assert success["description"]
        else:
            assert success["content"]["application/json"]["example"]


def test_catalog_filter_sort_page_and_binding_crud(domain_client):
    client, _runtime, admin, *_ = domain_client
    catalog = client.get(
        "/api/management/v1/model-catalog?sort=provider&page=1&pageSize=2",
        headers=admin,
    )
    assert catalog.status_code == 200
    payload = catalog.json()
    assert len(payload["data"]) == 2
    assert payload["meta"]["total"] >= 2
    assert payload["meta"]["hasNext"] is True
    selected = payload["data"][0]
    response = client.put(
        "/api/management/v1/model-metadata/client-visible/binding",
        headers=admin,
        json={
            "scope": "global",
            "targetModelId": selected["key"],
            "providerId": selected["providerId"],
        },
    )
    assert response.status_code == 200, response.text
    detail = response.json()["data"]
    assert detail["modelId"] == "client-visible"
    assert detail["target"] == selected["key"]
    assert detail["scope"] == "global"
    assert detail["revision"].startswith("rev_")

    listed = client.get(
        "/api/management/v1/model-metadata?query=client-visible&pageSize=1",
        headers=admin,
    )
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1
    got = client.get(
        "/api/management/v1/model-metadata/client-visible",
        headers=admin,
    )
    assert got.status_code == 200
    assert got.json()["data"]["raw"] is not None
    stale = client.delete(
        "/api/management/v1/model-metadata/client-visible/binding",
        headers={**admin, "If-Match": "rev_stale"},
    )
    assert stale.status_code == 409
    deleted = client.delete(
        "/api/management/v1/model-metadata/client-visible/binding",
        headers={**admin, "If-Match": detail["revision"]},
    )
    assert deleted.status_code == 204
    assert model_metadata.resolve_binding("client-visible") is None


def test_inventory_filters_and_total(domain_client, monkeypatch):
    client, _runtime, admin, *_ = domain_client
    items = [
        model_metadata.ModelInventoryItem(
            scope_key=f"api:channel-{index}", scope_type="api", scope_label=f"Channel {index}",
            client_visible_model=f"model-{index}", outbound_model=f"upstream-{index}",
        )
        for index in range(3)
    ]
    monkeypatch.setattr(model_metadata, "inventory_items", lambda: items)
    response = client.get(
        "/api/management/v1/models/inventory?query=model&page=2&pageSize=2&sort=modelId",
        headers=admin,
    )
    assert response.status_code == 200
    assert len(response.json()["data"]) == 1
    assert response.json()["meta"]["total"] == 3
    assert response.json()["meta"]["hasNext"] is False


def test_metadata_sync_returns_202_and_reaches_terminal_without_network(
    domain_client, monkeypatch,
):
    client, _runtime, admin, *_ = domain_client
    monkeypatch.setattr(model_pricing, "refresh_remote_catalog_sync", lambda: False)
    monkeypatch.setattr(model_pricing, "reload_local_catalog", lambda: None)
    monkeypatch.setattr(model_metadata, "auto_sync_metadata", lambda _items=None: {
        "scanned": 0, "created": [], "updated": [], "unchanged": [],
        "unmatched": [], "success": 0,
    })
    response = client.post(
        "/api/management/v1/model-metadata/actions/sync",
        headers={**admin, "Idempotency-Key": "metadata-sync-test"},
        json={"scope": "full"},
    )
    assert response.status_code == 202
    operation_id = response.json()["data"]["id"]
    replay = client.post(
        "/api/management/v1/model-metadata/actions/sync",
        headers={**admin, "Idempotency-Key": "metadata-sync-test"},
        json={"scope": "full"},
    )
    assert replay.status_code == 202
    assert replay.json()["data"]["id"] == operation_id
    conflict = client.post(
        "/api/management/v1/model-metadata/actions/sync",
        headers={**admin, "Idempotency-Key": "metadata-sync-test"},
        json={"scope": "channel", "channelId": "api:different"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "STATE_CONFLICT"
    terminal = None
    for _ in range(100):
        polled = client.get(
            f"/api/management/v1/operations/{operation_id}", headers=admin
        )
        assert polled.status_code == 200
        terminal = polled.json()["data"]
        if terminal["status"] in {"succeeded", "failed"}:
            break
        time.sleep(0.005)
    assert terminal["status"] == "succeeded"
    assert terminal["result"]["catalog"] == "local"
    assert "token" not in repr(terminal).lower()


def test_metadata_schema_validation_and_missing_ids(domain_client):
    client, _runtime, admin, *_ = domain_client
    invalid = client.put(
        "/api/management/v1/model-metadata/example/binding",
        headers=admin,
        json={
            "scope": "oauth", "targetModelId": "p/m", "providerId": "p",
            "unknown": "x",
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["fields"]
    assert client.get(
        "/api/management/v1/model-metadata/missing", headers=admin
    ).status_code == 404
    assert client.post(
        "/api/management/v1/model-metadata/actions/sync",
        headers=admin,
        json={"scope": "channel", "channelId": "api:missing"},
    ).status_code == 404

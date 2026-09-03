from __future__ import annotations

import time

import pytest

from src import config
from src.proxy import manager as proxy_manager
from src.tests.test_management_mapping_support import domain_client, operation_map


PROXY_OPERATIONS = {
    "listProxies", "createProxies", "getProxy", "updateProxy", "deleteProxy",
    "testProxy", "listProxyGroups", "createProxyGroups", "getProxyGroup",
    "updateProxyGroup", "deleteProxyGroup", "testProxyGroup",
    "getProxyRouting", "updateProxyRouting",
}


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("get", "/api/management/v1/proxies", None),
        ("post", "/api/management/v1/proxies", {"name": "edge", "url": "socks5://127.0.0.1:1080"}),
        ("get", "/api/management/v1/proxies/edge", None),
        ("patch", "/api/management/v1/proxies/edge", {"name": "renamed"}),
        ("delete", "/api/management/v1/proxies/edge", None),
        ("post", "/api/management/v1/proxies/edge/actions/test", None),
        ("get", "/api/management/v1/proxy-groups", None),
        ("post", "/api/management/v1/proxy-groups", {"name": "group", "members": ["direct"]}),
        ("get", "/api/management/v1/proxy-groups/group", None),
        ("patch", "/api/management/v1/proxy-groups/group", {"members": []}),
        ("delete", "/api/management/v1/proxy-groups/group", None),
        ("post", "/api/management/v1/proxy-groups/group/actions/test", None),
        ("get", "/api/management/v1/proxy-routing", None),
        ("patch", "/api/management/v1/proxy-routing", {"directFallback": True}),
    ],
)
def test_proxy_operations_require_session_and_capability(domain_client, method, path, body):
    client, _runtime, _admin, read_only, denied = domain_client
    assert client.request(method, path, json=body).status_code == 401
    forbidden = denied if method == "get" else read_only
    response = client.request(method, path, headers=forbidden, json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CAPABILITY_DENIED"


def test_proxy_openapi_typed_examples_and_write_only_secret(domain_client):
    client, *_ = domain_client
    operations = operation_map(client)
    assert PROXY_OPERATIONS <= set(operations)
    for operation_id in PROXY_OPERATIONS:
        operation = operations[operation_id]
        assert operation["tags"]
        assert operation.get("security") == [{"ManagementSession": []}]
        success = next(value for code, value in operation["responses"].items() if code.startswith("2"))
        if operation_id in {"deleteProxy", "deleteProxyGroup"}:
            assert success["description"]
        else:
            assert success["content"]["application/json"]["example"]
    document = client.get("/openapi.json").json()
    create_url = document["components"]["schemas"]["CreateProxyRequest"]["properties"]["url"]
    update_url = document["components"]["schemas"]["UpdateProxyRequest"]["properties"]["url"]
    assert create_url["writeOnly"] is True
    # Optional SecretStr is represented as anyOf in Pydantic, while writeOnly stays on the property.
    assert update_url["writeOnly"] is True
    serialized = repr(document)
    assert "private-password" not in serialized


def _create_proxy(client, headers, name, *, password="private-password"):
    response = client.post(
        "/api/management/v1/proxies",
        headers=headers,
        json={"name": name, "url": f"socks5://user:{password}@127.0.0.1:1080"},
    )
    assert response.status_code == 201, response.text
    assert password not in response.text
    assert response.json()["data"]["maskedUrl"] == "socks5://user:***@127.0.0.1:1080"
    return response.json()["data"]


def test_proxy_crud_list_filter_pagination_secret_and_reference_cascade(domain_client):
    client, runtime, admin, *_ = domain_client
    first = _create_proxy(client, admin, "edge-a")
    _create_proxy(client, admin, "edge-b")
    _create_proxy(client, admin, "edge-c")
    listed = client.get(
        "/api/management/v1/proxies?type=socks5&query=edge&sort=name&page=2&pageSize=2",
        headers=admin,
    )
    assert listed.status_code == 200
    assert [item["name"] for item in listed.json()["data"]] == ["edge-c"]
    assert listed.json()["meta"]["total"] == 3

    group = client.post(
        "/api/management/v1/proxy-groups", headers=admin,
        json={"name": "primary", "members": ["edge-a", "direct"]},
    )
    assert group.status_code == 201
    route = client.patch(
        "/api/management/v1/proxy-routing", headers=admin,
        json={"default": "primary", "functions": {"telegram": "edge-a"}},
    )
    assert route.status_code == 200
    revision = client.get(
        "/api/management/v1/proxies/edge-a", headers=admin
    ).json()["data"]["revision"]
    renamed = client.patch(
        "/api/management/v1/proxies/edge-a",
        headers={**admin, "If-Match": revision},
        json={"name": "edge-renamed"},
    )
    assert renamed.status_code == 200
    assert client.get(
        "/api/management/v1/proxy-groups/primary", headers=admin
    ).json()["data"]["members"] == ["edge-renamed", "direct"]
    assert client.get(
        "/api/management/v1/proxy-routing", headers=admin
    ).json()["data"]["functions"]["telegram"] == "edge-renamed"

    stale = client.delete(
        "/api/management/v1/proxies/edge-renamed",
        headers={**admin, "If-Match": "rev_stale"},
    )
    assert stale.status_code == 409
    current_revision = renamed.json()["data"]["revision"]
    deleted = client.delete(
        "/api/management/v1/proxies/edge-renamed",
        headers={**admin, "If-Match": current_revision},
    )
    assert deleted.status_code == 204
    assert client.get(
        "/api/management/v1/proxy-groups/primary", headers=admin
    ).json()["data"]["members"] == ["direct"]
    routing = client.get("/api/management/v1/proxy-routing", headers=admin).json()["data"]
    assert "telegram" not in routing["functions"]
    assert "private-password" not in repr(runtime.state_store.audit_snapshot())
    assert "private-password" not in repr(config.get().get("network", {}).get("routing", {}))


def test_proxy_group_rename_clear_delete_and_conflicts(domain_client):
    client, _runtime, admin, *_ = domain_client
    _create_proxy(client, admin, "edge")
    created = client.post(
        "/api/management/v1/proxy-groups", headers=admin,
        json={"name": "old-group", "members": ["edge"]},
    )
    revision = created.json()["data"]["revision"]
    assert client.patch(
        "/api/management/v1/proxy-routing", headers=admin,
        json={"default": "old-group"},
    ).status_code == 200
    revision = client.get(
        "/api/management/v1/proxy-groups/old-group", headers=admin
    ).json()["data"]["revision"]
    renamed = client.patch(
        "/api/management/v1/proxy-groups/old-group",
        headers={**admin, "If-Match": revision},
        json={"name": "new-group", "members": []},
    )
    assert renamed.status_code == 200
    assert renamed.json()["data"]["members"] == []
    assert client.get(
        "/api/management/v1/proxy-routing", headers=admin
    ).json()["data"]["default"] == "new-group"
    conflict = client.post(
        "/api/management/v1/proxy-groups", headers=admin,
        json={"name": "edge", "members": ["direct"]},
    )
    assert conflict.status_code == 409
    deleted = client.delete(
        "/api/management/v1/proxy-groups/new-group",
        headers={**admin, "If-Match": renamed.json()["data"]["revision"]},
    )
    assert deleted.status_code == 204
    assert client.get(
        "/api/management/v1/proxy-routing", headers=admin
    ).json()["data"]["default"] == "direct"


def _poll(client, headers, operation_id):
    current = None
    for _ in range(100):
        response = client.get(
            f"/api/management/v1/operations/{operation_id}", headers=headers
        )
        assert response.status_code == 200
        current = response.json()["data"]
        if current["status"] in {"succeeded", "failed"}:
            return current
        time.sleep(0.005)
    return current


def test_proxy_and_group_probe_are_fake_202_operations(domain_client, monkeypatch):
    client, _runtime, admin, *_ = domain_client
    _create_proxy(client, admin, "edge", password="probe-secret")
    assert client.post(
        "/api/management/v1/proxy-groups", headers=admin,
        json={"name": "primary", "members": ["edge"]},
    ).status_code == 201

    async def fake_proxy(name, *, timeout):
        assert timeout == 10
        return {"ok": True, "ip": "203.0.113.10", "latency_ms": 12}

    async def fake_group(name, *, timeout):
        assert timeout == 10
        return [{"name": "edge", "ok": True, "ip": "203.0.113.10", "latency_ms": 12}]

    monkeypatch.setattr(proxy_manager, "test_proxy", fake_proxy)
    monkeypatch.setattr(proxy_manager, "test_group", fake_group)
    for path in (
        "/api/management/v1/proxies/edge/actions/test",
        "/api/management/v1/proxy-groups/primary/actions/test",
    ):
        response = client.post(path, headers=admin)
        assert response.status_code == 202
        terminal = _poll(client, admin, response.json()["data"]["id"])
        assert terminal["status"] == "succeeded"
        assert "probe-secret" not in repr(terminal)


def test_proxy_probe_idempotency_replay_and_payload_conflict(domain_client, monkeypatch):
    client, _runtime, admin, *_ = domain_client
    _create_proxy(client, admin, "edge-a", password="one-secret")
    _create_proxy(client, admin, "edge-b", password="two-secret")
    calls = []

    async def fake_proxy(name, *, timeout):
        calls.append((name, timeout))
        return {"ok": True, "ip": "203.0.113.20", "latency_ms": 8}

    monkeypatch.setattr(proxy_manager, "test_proxy", fake_proxy)
    headers = {**admin, "Idempotency-Key": "proxy-probe-replay"}
    first = client.post(
        "/api/management/v1/proxies/edge-a/actions/test", headers=headers
    )
    replay = client.post(
        "/api/management/v1/proxies/edge-a/actions/test", headers=headers
    )
    assert first.status_code == replay.status_code == 202
    assert first.json()["data"]["id"] == replay.json()["data"]["id"]
    conflict = client.post(
        "/api/management/v1/proxies/edge-b/actions/test", headers=headers
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "STATE_CONFLICT"
    _poll(client, admin, first.json()["data"]["id"])
    assert calls == [("edge-a", 10)]


def test_proxy_validation_missing_and_unknown_target(domain_client):
    client, _runtime, admin, *_ = domain_client
    invalid = client.post(
        "/api/management/v1/proxies", headers=admin,
        json={"name": "Bad Name", "url": "not://supported", "unknown": True},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["fields"]
    unknown = client.patch(
        "/api/management/v1/proxy-routing", headers=admin,
        json={"default": "missing-target"},
    )
    assert unknown.status_code == 422
    assert unknown.json()["error"]["fields"][0]["path"] == "default"
    assert client.get(
        "/api/management/v1/proxies/missing", headers=admin
    ).status_code == 404
    assert client.get(
        "/api/management/v1/proxy-groups/missing", headers=admin
    ).status_code == 404

from __future__ import annotations

import asyncio
import copy
import time
from urllib.parse import quote

from src import config, model_mapping, model_metadata, model_pricing, state_db
from src.channel import registry
from src.management_api.routers.oauth import router as oauth_router
from src.management_api.routers.oauth_support import get_oauth_control_dependency
from src.management_control.oauth import OAuthBackend, OAuthControl
from src.management_control.proxy import ProxyControl
from src.proxy import manager as proxy_manager
from src.proxy.connector import SOCKS5Connector, connector_from_config, parse_proxy_url
from src.tests.test_management_mapping_support import domain_client


class _ModelChannel:
    def __init__(self, model_id: str) -> None:
        self.key = "api:s3-route"
        self.type = "api"
        self.protocol = "anthropic"
        self.provider = "test"
        self.models = [model_id]

    def list_client_models(self):
        return list(self.models)

    def supports_model(self, model_id: str):
        return model_id if model_id in self.models else None


def _encoded(value: str) -> str:
    return quote(value, safe="")


def _poll_operation(client, headers, operation_id: str) -> dict:
    for _ in range(100):
        response = client.get(
            f"/api/management/v1/operations/{operation_id}", headers=headers,
        )
        assert response.status_code == 200, response.text
        operation = response.json()["data"]
        if operation["status"] in {"succeeded", "failed"}:
            return operation
        time.sleep(0.005)
    raise AssertionError(f"operation {operation_id} did not finish")


def test_all_eight_model_resource_operations_accept_encoded_multisegment_ids(
    domain_client, monkeypatch,
):
    client, _runtime, admin, *_ = domain_client
    resource_id = "vendor/family/actions/sync/binding:@+$,;=?#[]"
    path_id = _encoded(resource_id)

    mapping = client.put(
        f"/api/management/v1/model-mappings/{path_id}",
        headers=admin,
        json={"realModel": "upstream/real-model"},
    )
    assert mapping.status_code == 200, mapping.text
    assert mapping.json()["data"]["alias"] == resource_id
    assert model_mapping.get_ingress_map("global")[resource_id] == "upstream/real-model"
    assert client.delete(
        f"/api/management/v1/model-mappings/{path_id}",
        headers={**admin, "If-Match": mapping.json()["data"]["revision"]},
    ).status_code == 204

    catalog = model_pricing.catalog_models()[0]
    metadata = client.put(
        f"/api/management/v1/model-metadata/{path_id}/binding",
        headers=admin,
        json={
            "scope": "global",
            "targetModelId": catalog["key"],
            "providerId": catalog["provider_id"],
        },
    )
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["data"]["modelId"] == resource_id
    detail = client.get(
        f"/api/management/v1/model-metadata/{path_id}", headers=admin,
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["data"]["modelId"] == resource_id
    assert client.delete(
        f"/api/management/v1/model-metadata/{path_id}/binding",
        headers={**admin, "If-Match": metadata.json()["data"]["revision"]},
    ).status_code == 204

    channel = _ModelChannel(resource_id)
    monkeypatch.setattr(registry, "all_channels", lambda: [channel])
    inventory = model_metadata.ModelInventoryItem(
        scope_key=channel.key,
        scope_type="api",
        scope_label="S3 route",
        client_visible_model=resource_id,
        outbound_model="upstream/real-model",
    )
    monkeypatch.setattr(model_metadata, "inventory_items", lambda: [inventory])

    order = client.get(
        f"/api/management/v1/load-balancing/model-orders/{path_id}", headers=admin,
    )
    assert order.status_code == 200, order.text
    assert order.json()["data"]["modelId"] == resource_id
    replaced = client.put(
        f"/api/management/v1/load-balancing/model-orders/{path_id}",
        headers={**admin, "If-Match": order.json()["data"]["revision"]},
        json={"order": [channel.key]},
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["data"]["modelId"] == resource_id
    assert client.delete(
        f"/api/management/v1/load-balancing/model-orders/{path_id}",
        headers={**admin, "If-Match": replaced.json()["data"]["revision"]},
    ).status_code == 204

    # Same-method static route remains reachable after installing the path converter.
    bulk = client.put(
        "/api/management/v1/load-balancing/model-orders",
        headers={**admin, "If-Match": client.get(
            "/api/management/v1/load-balancing", headers=admin,
        ).json()["data"]["revision"]},
        json={"modelIds": [resource_id], "order": [channel.key]},
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json()["data"]["orders"][0]["modelId"] == resource_id

    monkeypatch.setattr(model_pricing, "refresh_remote_catalog_sync", lambda: False)
    monkeypatch.setattr(model_pricing, "reload_local_catalog", lambda: None)
    monkeypatch.setattr(
        model_metadata,
        "auto_sync_metadata",
        lambda _items=None: {
            "scanned": len(_items or []),
            "created": [],
            "updated": [],
            "unchanged": [],
            "unmatched": [],
            "success": 0,
        },
    )
    sync = client.post(
        "/api/management/v1/model-metadata/actions/sync",
        headers={**admin, "Idempotency-Key": "s3-static-sync-route"},
        json={"scope": "full"},
    )
    assert sync.status_code == 202, sync.text
    assert _poll_operation(client, admin, sync.json()["data"]["id"])["status"] == "succeeded"


def test_oauth_api_account_id_round_trips_through_metadata_and_proxy_routing(
    domain_client, monkeypatch,
):
    client, _runtime, admin, *_ = domain_client
    account = {
        "provider": "claude",
        "type": "claude",
        "email": "routing@example.test",
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "enabled": True,
        "models": ["claude-sonnet-4-5"],
    }
    config.update(lambda current: current.__setitem__("oauthAccounts", [account]))
    owns_state_store = False
    try:
        state_db.get_store()
    except RuntimeError:
        state_db.init()
        owns_state_store = True
    registry.rebuild_from_config()

    oauth_control = OAuthControl(OAuthBackend())
    client.app.include_router(oauth_router, prefix="/api/management/v1")
    client.app.dependency_overrides[get_oauth_control_dependency] = lambda: oauth_control

    try:
        listed = client.get("/api/management/v1/oauth/accounts", headers=admin)
        assert listed.status_code == 200, listed.text
        account_id = listed.json()["data"]["items"][0]["accountId"]
        assert account_id == "claude:routing@example.test"
        channel_key = f"oauth:{account_id}"
        assert registry.get_channel(channel_key) is not None

        inventory_response = client.get(
            "/api/management/v1/models/inventory", headers=admin,
        )
        assert inventory_response.status_code == 200, inventory_response.text
        inventory = next(
            item for item in inventory_response.json()["data"]
            if item["accountId"] == account_id
        )
        assert inventory["channelId"] == channel_key
        assert "oauth:" not in inventory["accountId"]

        catalog = next(
            item for item in model_pricing.catalog_models()
            if item["provider_id"] == "anthropic"
        )
        model_id = inventory["modelId"]
        model_path = _encoded(model_id)
        created = client.put(
            f"/api/management/v1/model-metadata/{model_path}/binding",
            headers=admin,
            json={
                "scope": "oauth",
                "targetModelId": catalog["key"],
                "providerId": catalog["provider_id"],
                "accountId": account_id,
                "outboundModel": inventory["outboundModel"],
            },
        )
        assert created.status_code == 200, created.text
        metadata = created.json()["data"]
        assert metadata["scopeId"] == account_id
        assert any(
            binding.scope_key == channel_key
            for binding in model_metadata.list_bindings()
        )

        detail = client.get(
            f"/api/management/v1/model-metadata/{model_path}",
            headers=admin,
            params={"scopeId": account_id},
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["data"]["scopeId"] == account_id
        metadata_list = client.get(
            "/api/management/v1/model-metadata",
            headers=admin,
            params={"scope": "oauth", "scopeId": account_id},
        )
        assert metadata_list.status_code == 200, metadata_list.text
        assert metadata_list.json()["data"]
        assert all(
            item["scopeId"] in {None, account_id}
            for item in metadata_list.json()["data"]
        )

        before_missing = copy.deepcopy(config.get())
        missing_binding = client.put(
            f"/api/management/v1/model-metadata/{model_path}/binding",
            headers=admin,
            json={
                "scope": "oauth",
                "targetModelId": catalog["key"],
                "providerId": catalog["provider_id"],
                "accountId": "claude:missing@example.test",
                "outboundModel": inventory["outboundModel"],
            },
        )
        assert missing_binding.status_code == 404
        assert missing_binding.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
        assert config.get() == before_missing

        deleted = client.delete(
            f"/api/management/v1/model-metadata/{model_path}/binding",
            headers={**admin, "If-Match": metadata["revision"]},
            params={"scope": "oauth", "accountId": account_id},
        )
        assert deleted.status_code == 204, deleted.text
        assert not any(
            binding.scope_key == channel_key
            and binding.client_visible_model == model_id
            for binding in model_metadata.list_bindings()
        )

        monkeypatch.setattr(model_pricing, "refresh_remote_catalog_sync", lambda: False)
        monkeypatch.setattr(model_pricing, "reload_local_catalog", lambda: None)
        monkeypatch.setattr(
            model_metadata,
            "auto_sync_metadata",
            lambda items=None: {
                "scanned": len(items or []),
                "created": [],
                "updated": [],
                "unchanged": [],
                "unmatched": [],
                "success": 0,
            },
        )
        sync = client.post(
            "/api/management/v1/model-metadata/actions/sync",
            headers={**admin, "Idempotency-Key": "s3-canonical-account-sync"},
            json={"scope": "account", "accountId": account_id},
        )
        assert sync.status_code == 202, sync.text
        terminal = _poll_operation(client, admin, sync.json()["data"]["id"])
        assert terminal["status"] == "succeeded"
        assert terminal["result"]["scanned"] >= 1

        routing = client.patch(
            "/api/management/v1/proxy-routing",
            headers=admin,
            json={"accounts": {account_id: "direct"}},
        )
        assert routing.status_code == 200, routing.text
        assert routing.json()["data"]["accounts"] == {account_id: "direct"}
        assert config.get()["network"]["routing"]["accounts"] == {
            channel_key: "direct"
        }
        fetched_routing = client.get(
            "/api/management/v1/proxy-routing", headers=admin,
        )
        assert fetched_routing.status_code == 200
        assert fetched_routing.json()["data"]["accounts"] == {
            account_id: "direct"
        }

        before_stale = copy.deepcopy(config.get()["network"]["routing"])
        stale = client.patch(
            "/api/management/v1/proxy-routing",
            headers={**admin, "If-Match": "rev_stale"},
            json={"accounts": {account_id: None}},
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "REVISION_CONFLICT"
        assert config.get()["network"]["routing"] == before_stale

        missing_routing = client.patch(
            "/api/management/v1/proxy-routing",
            headers=admin,
            json={"accounts": {"claude:missing@example.test": "direct"}},
        )
        assert missing_routing.status_code == 404
        assert missing_routing.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
        assert config.get()["network"]["routing"] == before_stale

        account_proxy = client.post(
            "/api/management/v1/proxies",
            headers=admin,
            json={"name": "account-edge", "url": "socks5://127.0.0.1:1080"},
        )
        assert account_proxy.status_code == 201, account_proxy.text
        account_route = client.patch(
            "/api/management/v1/proxy-routing",
            headers=admin,
            json={"accounts": {account_id: "account-edge"}},
        )
        assert account_route.status_code == 200, account_route.text
        referenced = client.delete(
            "/api/management/v1/proxies/account-edge",
            headers={
                **admin,
                "If-Match": client.get(
                    "/api/management/v1/proxies/account-edge", headers=admin,
                ).json()["data"]["revision"],
            },
        )
        assert referenced.status_code == 409, referenced.text
        assert referenced.json()["error"]["fields"] == [{
            "path": f"routing.accounts.{account_id}",
            "code": "RESOURCE_IN_USE",
            "message": "resource is still referenced",
        }]
    finally:
        client.app.dependency_overrides.pop(get_oauth_control_dependency, None)
        config.update(
            lambda current: (
                current.clear(), current.update(copy.deepcopy(config.DEFAULT_CONFIG))
            )
        )
        registry.rebuild_from_config()
        if owns_state_store:
            state_db.close()


def _assert_constructible_socks_connector(name: str, expected_url: str) -> None:
    connector = proxy_manager.get_connector(name)
    assert isinstance(connector, SOCKS5Connector)
    assert connector.url == expected_url
    client = connector.create_httpx_client()
    asyncio.run(client.aclose())


def test_ipv6_socks_create_patch_and_config_reload_keep_real_connector(domain_client):
    client, _runtime, admin, *_ = domain_client
    proxy_manager.init()

    created_url = "socks5://user%40name:p%3Aass@[2001:db8::1]:1080#tg-created"
    created_normalized = "socks5://user%40name:p%3Aass@[2001:db8::1]:1080"
    assert parse_proxy_url("socks5://[::1]:1080") == {
        "type": "socks5",
        "url": "socks5://[::1]:1080",
        "name": "",
    }
    parsed = ProxyControl().parse_proxy_url(created_url)
    assert parsed == {
        "type": "socks5",
        "url": created_normalized,
        "name": "tg-created",
    }
    assert isinstance(connector_from_config("parsed", parsed), SOCKS5Connector)

    created = client.post(
        "/api/management/v1/proxies",
        headers=admin,
        json={"name": "ipv6-edge", "url": created_url},
    )
    assert created.status_code == 201, created.text
    assert config.get()["network"]["proxies"]["ipv6-edge"]["url"] == created_normalized
    config.reload()
    _assert_constructible_socks_connector("ipv6-edge", created_normalized)

    patched_url = "socks5h://next:p%40ss@[::1]:2080#tg-patched"
    patched_normalized = "socks5://next:p%40ss@[::1]:2080"
    patched = client.patch(
        "/api/management/v1/proxies/ipv6-edge",
        headers={**admin, "If-Match": created.json()["data"]["revision"]},
        json={"url": patched_url},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["data"]["maskedUrl"] == "socks5://next:***@[::1]:2080"
    assert config.get()["network"]["proxies"]["ipv6-edge"]["url"] == patched_normalized
    config.reload()
    _assert_constructible_socks_connector("ipv6-edge", patched_normalized)

    reparsed = parse_proxy_url(patched_url)
    assert reparsed["name"] == "tg-patched"
    assert reparsed["url"] == patched_normalized

"""Domain parity between real P5 Telegram menus and Management API routes.

The strict byte-for-byte Telegram payload side of these same domains remains
owned by the three frozen ``test_tg_contract_*_baseline.py`` segments.
"""

from __future__ import annotations

import copy

from src import config, model_mapping
from src.proxy import manager as proxy_manager
from src.telegram import states, ui
from src.telegram.menus import load_balancing_menu, mapping_menu, proxy_menu
from src.tests.test_management_mapping_support import domain_client


def _replace_config(snapshot: dict) -> None:
    config.update(
        lambda current: (current.clear(), current.update(copy.deepcopy(snapshot)))
    )


def _fake_telegram_transport(monkeypatch):
    calls: list[dict] = []

    def api(method, data=None):
        calls.append({"method": method, "payload": copy.deepcopy(data or {})})
        result = {"message_id": 501} if method == "sendMessage" else {}
        return {"ok": True, "result": result}

    monkeypatch.setattr(ui, "api", api)
    states.clear_all()
    ui._code_to_name.clear()
    return calls


def test_mapping_api_and_migrated_telegram_read_write_parity(
    domain_client, monkeypatch,
):
    client, _runtime, admin, *_ = domain_client
    initial = copy.deepcopy(config.DEFAULT_CONFIG)
    initial["modelMapping"] = {
        "global": {"parity-alias": "real-model"},
        "anthropic": {"parity-alias": "legacy-shadow"},
    }
    _replace_config(initial)
    calls = _fake_telegram_transport(monkeypatch)

    assert mapping_menu.handle_callback(42, 77, "cb-map-read", "map:line:glo")
    telegram_read = dict(model_mapping.get_ingress_map("global"))
    alias_code = ui.register_code("map:alias:global:parity-alias")
    assert mapping_menu.handle_callback(
        42, 77, "cb-map-write", f"map:rm_ok:glo:{alias_code}"
    )
    telegram_final = copy.deepcopy(config.get()["modelMapping"])
    assert calls

    _replace_config(initial)
    api_read = client.get(
        "/api/management/v1/model-mappings?sort=alias", headers=admin
    )
    assert api_read.status_code == 200, api_read.text
    assert {item["alias"]: item["realModel"] for item in api_read.json()["data"]} == (
        telegram_read
    )
    revision = api_read.json()["meta"]["revision"]
    deleted = client.delete(
        "/api/management/v1/model-mappings/parity-alias",
        headers={**admin, "If-Match": revision},
    )
    assert deleted.status_code == 204, deleted.text
    assert config.get()["modelMapping"] == telegram_final


def test_load_balancing_api_and_migrated_telegram_read_write_parity(
    domain_client, monkeypatch,
):
    client, _runtime, admin, *_ = domain_client
    initial = copy.deepcopy(config.DEFAULT_CONFIG)
    initial["channelSelection"] = "smart"
    _replace_config(initial)
    calls = _fake_telegram_transport(monkeypatch)

    assert load_balancing_menu.handle_callback(
        42, 77, "cb-lb-read", "menu:loadbalancing"
    )
    telegram_read = config.get()["channelSelection"]
    assert load_balancing_menu.handle_callback(
        42, 77, "cb-lb-write", "lb:mode:priority"
    )
    telegram_final = copy.deepcopy(config.get())
    assert calls

    _replace_config(initial)
    api_read = client.get("/api/management/v1/load-balancing", headers=admin)
    assert api_read.status_code == 200, api_read.text
    assert api_read.json()["data"]["mode"] == telegram_read
    updated = client.patch(
        "/api/management/v1/load-balancing",
        headers=admin,
        json={"mode": "priority"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["mode"] == "priority"
    assert config.get() == telegram_final


def test_proxy_api_and_migrated_telegram_read_write_parity(
    domain_client, monkeypatch,
):
    client, _runtime, admin, *_ = domain_client
    initial = copy.deepcopy(config.DEFAULT_CONFIG)
    initial["network"] = {
        "proxies": {},
        "groups": {},
        "routing": {"default": "direct", "directFallback": False},
    }
    _replace_config(initial)
    proxy_manager.init()
    calls = _fake_telegram_transport(monkeypatch)

    assert proxy_menu.handle_callback(42, 77, "cb-proxy-read", "px:routing")
    telegram_read = copy.deepcopy(proxy_manager.get_routing())
    assert proxy_menu.handle_callback(42, 77, "cb-proxy-write", "px:rt_df")
    telegram_final = copy.deepcopy(config.get()["network"])
    assert calls

    _replace_config(initial)
    proxy_manager.init()
    api_read = client.get("/api/management/v1/proxy-routing", headers=admin)
    assert api_read.status_code == 200, api_read.text
    assert api_read.json()["data"]["default"] == telegram_read["default"]
    assert api_read.json()["data"]["directFallback"] == telegram_read["directFallback"]
    updated = client.patch(
        "/api/management/v1/proxy-routing",
        headers=admin,
        json={"directFallback": True},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["directFallback"] is True
    assert config.get()["network"] == telegram_final

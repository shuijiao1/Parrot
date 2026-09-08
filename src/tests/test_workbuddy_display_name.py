"""WorkBuddy TG names: no-email accounts, route identity and legacy compatibility."""
from __future__ import annotations

import copy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src import config, oauth_manager as om
from src.telegram import states, ui
from src.telegram.menus import proxy_menu


@pytest.mark.parametrize("realm", ["cn", "global"])
@pytest.mark.parametrize("with_family", [False, True])
@pytest.mark.parametrize("fields,expected", [
    ({"label": "备注 A", "nickname": "昵称 A", "email": "a@example.test", "uid": "uid-a"}, "备注 A"),
    ({"nickname": "昵称 A", "email": "a@example.test", "uid": "uid-a"}, "昵称 A"),
    ({"email": "a@example.test", "uid": "uid-a"}, "a@example.test"),
    ({"uid": "uid-a"}, "uid-a"),
    ({}, "?"),
])
def test_workbuddy_uses_existing_account_name_priority(monkeypatch, realm, with_family, fields, expected):
    acc = {"provider": "workbuddy", "realm": realm, **fields}
    before = copy.deepcopy(acc)
    monkeypatch.setattr(om, "get_account", lambda key: acc)
    name = ui.channel_display_name(f"oauth:workbuddy:{realm}:uid-a:p", with_family=with_family)
    suffix = ui.provider_tag("workbuddy", rich=False) if with_family else ui.provider_label("workbuddy")
    assert name == f"{expected} · {suffix}"
    assert acc == before


@pytest.mark.parametrize("provider,expected", [
    ("cursor", "保留备注"), ("openai", "a@example.test"), ("xai", "a@example.test"),
    ("antigravity", "a@example.test"), ("claude", "a@example.test"),
])
def test_other_providers_keep_existing_name_semantics(monkeypatch, provider, expected):
    acc = {"provider": provider, "label": "保留备注", "nickname": "不得替换旧规则", "email": "a@example.test"}
    monkeypatch.setattr(om, "get_account", lambda key: acc)
    monkeypatch.setattr(om, "list_accounts", lambda: [acc])
    assert ui.channel_display_name(f"oauth:{provider}:fixture", with_family=False) == f"{expected} · {ui.provider_label(provider)}"


def test_openai_workspace_disambiguation_stays_unchanged(monkeypatch):
    acc = {"provider": "openai", "email": "same@example.test", "workspace_name": "工作区 A"}
    monkeypatch.setattr(om, "get_account", lambda key: acc)
    monkeypatch.setattr(om, "list_accounts", lambda: [acc, dict(acc, workspace_name="工作区 B")])
    assert ui.channel_display_name("oauth:openai:fixture", with_family=False) == "same@example.test · 工作区 A · OpenAI"


def test_both_workbuddy_route_labels_and_picker_keep_exact_account_keys(monkeypatch):
    entries = [
        {"provider": "workbuddy", "realm": "cn", "uid": "same-id", "email": "", "label": "中国 <A>", "nickname": "国内昵称"},
        {"provider": "workbuddy", "realm": "global", "uid": "same-id", "email": "", "label": "", "nickname": "国际 &B"},
    ]
    keys = ["oauth:" + om.get_account_key(acc) for acc in entries]
    assert len(set(keys)) == 2
    cfg = {"oauthAccounts": entries, "network": {"routing": {"accounts": {keys[0]: "proxy-cn", keys[1]: "proxy-global"}}}}
    before = copy.deepcopy(cfg)
    monkeypatch.setattr(config, "get", lambda: cfg)
    monkeypatch.setattr(config, "update", Mock(side_effect=AssertionError("Rendering must not change config")))
    monkeypatch.setattr(proxy_menu, "_item_index", {})
    monkeypatch.setattr(proxy_menu.proxy_control, "get_routing_dict", lambda: cfg["network"]["routing"])
    monkeypatch.setattr(proxy_menu.proxy_control, "all_channels", lambda: [
        SimpleNamespace(type="oauth", key=key, provider="workbuddy") for key in keys])
    monkeypatch.setattr(proxy_menu, "_all_targets", lambda: [("direct", "🌐 direct")])
    monkeypatch.setattr(ui, "answer_cb", Mock())
    edit = Mock()
    monkeypatch.setattr(ui, "edit", edit)
    states.clear_all()
    try:
        assert proxy_menu.handle_callback(42, 900, "cb", "px:rt_accounts")
        text = edit.call_args.args[2]
        rows = edit.call_args.kwargs["reply_markup"]["inline_keyboard"]
        assert "中国 &lt;A&gt; · WorkBuddy" in text and "国际 &amp;B · WorkBuddy" in text
        assert "? · WorkBuddy" not in text
        assert rows[0][0]["text"] == "中国 <A> · WorkBuddy [proxy-cn]"
        assert rows[1][0]["text"] == "国际 &B · WorkBuddy [proxy-global]"
        assert rows[0][0]["callback_data"] == "px:rt_item:a:0"
        assert rows[1][0]["callback_data"] == "px:rt_item:a:1"
        for i, expected in enumerate(("中国 &lt;A&gt;", "国际 &amp;B")):
            assert proxy_menu.handle_callback(42, 900, "cb", f"px:rt_item:a:{i}")
            assert expected + " · WorkBuddy" in edit.call_args.args[2]
            assert states.get_state(42)["data"]["context"] == "accounts:" + keys[i]
        assert cfg == before
        config.update.assert_not_called()
    finally:
        states.clear_all()

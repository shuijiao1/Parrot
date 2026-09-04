"""Unicode sorting gate for the frozen Telegram load-balancing surface."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src import model_mapping
from src.channel import registry
from src.management_control.load_balancing import load_balancing_control
from src.telegram import states, ui
from src.telegram.menus import load_balancing_menu as menu


_MODELS = ["ß-model", "st-model", "ss-model"]
_BASELINE_ORDER = ["ss-model", "st-model", "ß-model"]
_BASELINE_CODES = ["14b019b5", "eb4983c6", "5d884c80"]


class _UnicodeChannel:
    key = "api:unicode"
    type = "api"
    protocol = "anthropic"
    enabled = True
    disabled_reason = None

    def list_client_models(self) -> list[str]:
        return list(_MODELS)


@pytest.fixture
def unicode_models(monkeypatch: pytest.MonkeyPatch):
    channel = _UnicodeChannel()
    monkeypatch.setattr(registry, "all_channels", lambda: [channel])
    monkeypatch.setattr(model_mapping, "get_ingress_map", lambda _line: {})
    monkeypatch.setattr(menu, "_effective_model_keys", lambda _model: [])
    monkeypatch.setattr(load_balancing_control, "has_model_priority", lambda _model: False)
    states.clear_all()
    ui._code_to_name.clear()
    yield
    states.clear_all()
    ui._code_to_name.clear()


def test_unicode_client_models_use_frozen_lower_order(unicode_models):
    # str.casefold() moves ß-model before st-model; v0.31.13 value.lower()
    # keeps ß as a distinct code point and therefore places it last.
    assert load_balancing_control.client_models() == _BASELINE_ORDER
    assert menu._client_models() == _BASELINE_ORDER


def test_unicode_tg_list_picker_and_short_codes_keep_baseline_order(unicode_models):
    text, keyboard = menu._models_text_and_kb(1)
    assert [text.index(f"<code>{model}</code>") for model in _BASELINE_ORDER] == sorted(
        text.index(f"<code>{model}</code>") for model in _BASELINE_ORDER
    )

    detail_buttons = keyboard["inline_keyboard"][0]
    assert [button["callback_data"] for button in detail_buttons] == [
        f"lb:model:{code}:1" for code in _BASELINE_CODES
    ]
    assert [menu._resolve_model_code(code) for code in _BASELINE_CODES] == _BASELINE_ORDER

    states.set_state(42, "lb_model_select", {"selected_models": list(_MODELS)})
    picker_text, picker_keyboard = menu._render_bulk_selection(42)
    assert "已选择：" + "、".join(
        f"<code>{model}</code>" for model in _BASELINE_ORDER
    ) in picker_text

    picker_buttons = [
        button
        for row in picker_keyboard["inline_keyboard"][:-1]
        for button in row
    ]
    assert [button["text"] for button in picker_buttons] == [
        f"✅ {model}" for model in _BASELINE_ORDER
    ]
    assert [button["callback_data"] for button in picker_buttons] == [
        f"lb:model_pick:{code}" for code in _BASELINE_CODES
    ]

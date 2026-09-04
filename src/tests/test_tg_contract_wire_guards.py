"""Narrow gates for Telegram wire distinctions proven missing by parity audit."""

from __future__ import annotations

import pytest

from src.telegram import ui
from src.tests.tg_contract import StrictMismatch, assert_strict_equal


def test_strict_comparator_rejects_json_object_key_reordering():
    expected = {"chat_id": 42, "text": "hello", "parse_mode": "HTML"}
    actual = {"text": "hello", "chat_id": 42, "parse_mode": "HTML"}

    with pytest.raises(StrictMismatch, match="object key order differs"):
        assert_strict_equal(expected, actual)


def test_delete_my_commands_keeps_explicit_empty_post_payload(monkeypatch):
    calls: list[tuple[str, dict | None]] = []

    def fake_api(method: str, data: dict | None = None):
        calls.append((method, data))
        return {"ok": True, "result": True}

    monkeypatch.setattr(ui, "api", fake_api)

    result = ui.delete_my_commands()

    assert result == {"ok": True, "result": True}
    assert calls == [("deleteMyCommands", {})]

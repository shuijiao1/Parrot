"""Strict v0.31.13 retention traces for TG-SYS-05."""
from __future__ import annotations

import pytest

from src.telegram import states
from src.telegram.menus import system_menu as sm
from src.tests.test_tg_contract_system_helpers import cases_for, run_and_compare

CASES = cases_for("TG-SYS-05")


def _first_code(e, days="7"):
    e.callback("sys:retention:days")
    e.text("sys_retention_days", days)
    return next(iter(sm._retention_pending))


def _plan_code(e, days="7"):
    first = _first_code(e, days)
    e.callback("sys:retention:scan:" + first)
    return next(iter(sm._retention_pending))


def _menu_toggle_and_busy(e):
    e.callback("sys:show:retention")
    e.callback("sys:retention:toggle_bodies")
    e.callback("sys:retention:toggle_bodies")
    e.callback("sys:retention:noop")
    e.callback("sys:retention:days")


def _days_validation_same(e):
    e.callback("sys:retention:days")
    e.text("sys_retention_days", "bad")
    e.text("sys_retention_days", "0")
    e.text("sys_retention_days", str(e.cfg["logRetention"]["days"]))


def _extend(e):
    e.callback("sys:retention:days")
    e.text("sys_retention_days", "9")


def _first_cancel(e):
    code = _first_code(e)
    assert len(code) == 8
    e.callback("sys:retention:cancel:" + code)
    e.callback("sys:retention:scan:" + code, "scan-after-cancel")


def _input_cancel(e):
    e.callback("sys:retention:days")
    e.callback("sys:retention:cancel_input")


def _scan_failure(e):
    code = _first_code(e)
    e.callback("sys:retention:scan:" + code)


def _plan_paging_cancel(e):
    code = _plan_code(e)
    e.callback("sys:retention:plan:" + code + ":1")
    e.callback("sys:retention:plan:" + code + ":0")
    e.callback("sys:retention:plan:bad")
    e.callback("sys:retention:plan:" + code + ":bad")
    e.callback("sys:retention:cancel:" + code)
    e.callback("sys:retention:commit:" + code, "commit-after-cancel")


def _commit(e):
    code = _plan_code(e)
    e.callback("sys:retention:commit:" + code, chat_id=43, cb_id="cb-wrong-chat")
    e.callback("sys:retention:commit:" + code)
    e.callback("sys:retention:commit:" + code, "repeat-commit")


def _ttl(e):
    first = _first_code(e)
    assert len(first) == 8
    e.advance(600)
    e.callback("sys:retention:scan:" + first, "first-plan-exactly-600-expired")
    # Telegram text state itself expires only once elapsed time is greater than 600.
    e.callback("sys:retention:days")
    e.advance(601)
    e.direct("state-get-after-601", lambda: states.get_state(42))


def _wrong_chat(e):
    first = _first_code(e)
    e.callback("sys:retention:scan:" + first, chat_id=43, cb_id="cb-wrong-chat")
    e.callback("sys:retention:scan:" + first)


def _forever(e):
    e.callback("sys:retention:forever")


RUNNERS = {
    "menu_toggle_busy": _menu_toggle_and_busy,
    "days_validation_same": _days_validation_same,
    "extend": _extend,
    "first_cancel": _first_cancel,
    "input_cancel": _input_cancel,
    "scan_failure": _scan_failure,
    "plan_paging_cancel": _plan_paging_cancel,
    "commit": _commit,
    "ttl": _ttl,
    "wrong_chat": _wrong_chat,
    "forever": _forever,
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["caseId"])
def test_system_retention_trace(case, monkeypatch):
    run_and_compare(case, monkeypatch, RUNNERS[case["entry"]["scenario"]])

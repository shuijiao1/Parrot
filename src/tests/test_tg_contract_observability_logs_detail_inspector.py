"""Strict v0.31.13 log detail and structured-body inspector traces."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from src import config, log_db
from src.telegram import states, ui
from src.telegram.menus import logs_menu
from src.tests.tg_contract import assert_strict_equal, load_jsonl
from src.tests.test_tg_contract_observability_cache_stats import (
    Capture, actual_case, install_config,
)

SEGMENT = Path(__file__).parent / "fixtures/tg_contract/v0.31.13/segments/observability.jsonl"
ALL_CASES = load_jsonl(SEGMENT)
OWN_CAPABILITIES = {"TG-LOG-03", "TG-LOG-04"}
CASES = [case for case in ALL_CASES if case["capabilityId"] in OWN_CAPABILITIES]


def _state_snapshot(chat_id: int = 42) -> dict[str, Any]:
    return {"chatId": chat_id, "state": deepcopy(states.get_state(chat_id))}


def _install(case, monkeypatch):
    capture = Capture()
    runtime = case["initialRuntime"]
    install_config(monkeypatch, case["initialConfig"])
    monkeypatch.setattr(ui, "api", capture.api)
    monkeypatch.setattr(ui, "send_document_text", capture.document)
    monkeypatch.setattr(states.time, "time", lambda: float(runtime.get("nowTs", 2000)))
    states.clear_all()
    ui._code_to_name.clear()
    monkeypatch.setattr(ui, "channel_display_name", lambda key, with_family=False: str(key).split(":", 1)[-1])
    monkeypatch.setattr(ui, "channel_provider", lambda key: "")
    monkeypatch.setattr(ui, "channel_provider_custom_emoji_html", lambda key: "")

    def detail(rid):
        if runtime.get("dbError"):
            raise RuntimeError(runtime["dbError"])
        by_id = runtime.get("detailsById") or {}
        if rid in by_id:
            return deepcopy(by_id[rid])
        return deepcopy(runtime.get("detail"))

    monkeypatch.setattr(log_db, "log_detail", detail)
    monkeypatch.setattr(log_db, "cost_for_log", lambda row: deepcopy(runtime.get("costMetrics") or {
        "cost_ticks": int((row or {}).get("cost_ticks") or 0),
        "costed_success": int((row or {}).get("costed_success") or 0),
        "unpriced_success": int((row or {}).get("unpriced_success") or 0),
    }))
    return capture


def _codes_final() -> dict[str, Any]:
    families: dict[str, int] = {}
    for value in ui._code_to_name.values():
        family = value.split(":", 1)[0] + ":" if ":" in value else "raw"
        families[family] = families.get(family, 0) + 1
    return {"registeredCodeCount": len(ui._code_to_name), "registeredCodeFamilies": families}


def _run_detail(case, monkeypatch):
    capture = _install(case, monkeypatch)
    entry = case["entry"]
    if entry.get("validShort", True):
        short = ui.register_code(entry.get("requestId", "REQ-DETAIL-1"))
    else:
        short = "deadbeef"
    list_short = logs_menu._list_state_code(entry.get("listState") or {"p": 1, "a": [], "m": [], "c": []})
    if entry.get("family") == "logs:dpage:":
        data = f"logs:dpage:{short}:{entry.get('detailPage', 1)}:{list_short}"
    else:
        data = f"logs:detail:{short}:{list_short}"
    handled = logs_menu.handle_callback(42, 77, "cb-detail", data)
    return actual_case(case, capture.calls, [], {"handled": handled, **_codes_final()})


def _run_body(case, monkeypatch):
    capture = _install(case, monkeypatch)
    entry = case["entry"]
    kind = entry["kind"]
    if entry.get("validShort", True):
        prefix = "logbody:" if kind == "request" else "logresp:"
        short = ui.register_code(prefix + entry["requestId"])
        list_short = logs_menu._list_state_code(entry.get("listState") or {"p": 1})
        payload = f"{short}:{list_short}"
    else:
        payload = "deadbeef:deadbeef"
    family = "logs:body:" if kind == "request" else "logs:response:"
    handled = logs_menu.handle_callback(42, 77, "cb-body", family + payload)
    return actual_case(case, capture.calls, [], {"handled": handled, **_codes_final()})


def _run_inspector(case, monkeypatch):
    capture = _install(case, monkeypatch)
    state = deepcopy(case["entry"]["inspectorState"])
    short = logs_menu._state_code(state)
    handled = logs_menu.handle_callback(42, 77, "cb-ins", f"logs:ins:{short}")
    return actual_case(case, capture.calls, [], {"handled": handled, **_codes_final()})


def _run_full(case, monkeypatch):
    capture = _install(case, monkeypatch)
    entry = case["entry"]
    short = logs_menu._state_code(deepcopy(entry["inspectorState"])) if entry.get("validShort", True) else "deadbeef"
    handled = logs_menu.handle_callback(42, 77, "cb-full", f"logs:full:{short}")
    return actual_case(case, capture.calls, [], {"handled": handled, **_codes_final()})


def _run_search_begin(case, monkeypatch):
    capture = _install(case, monkeypatch)
    entry = case["entry"]
    short = logs_menu._state_code(deepcopy(entry["inspectorState"])) if entry.get("validShort", True) else "deadbeef"
    handled = logs_menu.handle_callback(42, 77, "cb-search", f"logs:search:{short}")
    steps = [{"after": "callback", **_state_snapshot()}]
    return actual_case(case, capture.calls, steps, {"handled": handled, **_codes_final()})


def _run_search_text(case, monkeypatch):
    capture = _install(case, monkeypatch)
    entry = case["entry"]
    if entry.get("stateData") is not None:
        states.set_state(42, "logs_search", deepcopy(entry["stateData"]))
    before = _state_snapshot()
    handled = logs_menu.handle_text_state(42, entry.get("action", "logs_search"), entry["text"])
    steps = [{"after": "before_text", **before}, {"after": "text", **_state_snapshot()}]
    return actual_case(case, capture.calls, steps, {"handled": handled, **_codes_final()})


def _run_negative(case, monkeypatch):
    capture = _install(case, monkeypatch)
    handled = logs_menu.handle_callback(42, 77, "cb-negative", case["entry"]["callbackData"])
    return actual_case(case, capture.calls, [], {"handled": handled, **_codes_final()})


RUNNERS = {
    "detail": _run_detail,
    "body": _run_body,
    "inspector": _run_inspector,
    "full": _run_full,
    "search_begin": _run_search_begin,
    "search_text": _run_search_text,
    "negative": _run_negative,
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["caseId"])
def test_logs_detail_inspector_trace(case, monkeypatch):
    actual = RUNNERS[case["entry"]["scenario"]](case, monkeypatch)
    assert_strict_equal(case, actual)


def test_logs_detail_inspector_case_ids_are_bidirectional():
    declared = {
        "TG-LOG-03.detail-success-stage-round-attempt-usage-price-formula",
        "TG-LOG-03.detail-error-business-failure",
        "TG-LOG-03.detail-cancelled",
        "TG-LOG-03.detail-page-two-long-error",
        "TG-LOG-03.detail-short-expired",
        "TG-LOG-03.detail-query-failure",
        "TG-LOG-03.detail-missing-row",
        "TG-LOG-04.request-inspector-page-one-preview-counts",
        "TG-LOG-04.request-inspector-page-two-sort-filter",
        "TG-LOG-04.response-inspector",
        "TG-LOG-04.encrypted-unreadable-sanitize",
        "TG-LOG-04.unreadable-response-fallback",
        "TG-LOG-04.empty-search-result",
        "TG-LOG-04.full-item-chunks",
        "TG-LOG-04.full-item-document",
        "TG-LOG-04.full-item-expired",
        "TG-LOG-04.search-begin-state",
        "TG-LOG-04.search-begin-expired",
        "TG-LOG-04.search-text-success",
        "TG-LOG-04.search-text-clear",
        "TG-LOG-04.search-text-cancel",
        "TG-LOG-04.search-text-state-expired",
        "TG-LOG-04.body-short-expired",
        "TG-LOG-04.inspector-parse-failure",
        "TG-LOG-04.inspector-short-expired",
    }
    assert {case["caseId"] for case in CASES} == declared

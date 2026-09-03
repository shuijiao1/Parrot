"""Strict v0.31.13 request-log list and server-side filter traces."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from src import config, log_db, oauth_manager
from src.telegram import ui
from src.telegram.menus import logs_menu
from src.tests.tg_contract import assert_strict_equal, load_jsonl
from src.tests.test_tg_contract_observability_cache_stats import (
    Capture, actual_case, install_config,
)

SEGMENT = Path(__file__).parent / "fixtures/tg_contract/v0.31.13/segments/observability.jsonl"
ALL_CASES = load_jsonl(SEGMENT)
OWN_CAPABILITIES = {"TG-LOG-01", "TG-LOG-02"}
CASES = [case for case in ALL_CASES if case["capabilityId"] in OWN_CAPABILITIES]


def _matches(row: dict[str, Any], *, api_keys=None, models=None, channel_keys=None) -> bool:
    return (
        (not api_keys or row.get("api_key_name") in api_keys)
        and (not models or row.get("requested_model") in models)
        and (not channel_keys or row.get("final_channel_key") in channel_keys)
    )


def _install(case, monkeypatch):
    capture = Capture()
    runtime = case["initialRuntime"]
    install_config(monkeypatch, case["initialConfig"])
    monkeypatch.setattr(ui, "api", capture.api)
    ui._code_to_name.clear()
    queries: list[dict[str, Any]] = []
    rows = deepcopy(runtime.get("rows") or [])

    def filtered(**kwargs):
        return [row for row in rows if _matches(row, **kwargs)]

    def count(**kwargs):
        queries.append({"method": "recent_logs_count", "filters": deepcopy(kwargs)})
        return len(filtered(**kwargs))

    def recent(limit, offset=0, **kwargs):
        queries.append({
            "method": "recent_logs", "limit": limit, "offset": offset,
            "filters": deepcopy(kwargs),
        })
        return deepcopy(filtered(**kwargs)[offset:offset + limit])

    monkeypatch.setattr(log_db, "recent_logs_count", count)
    monkeypatch.setattr(log_db, "recent_logs", recent)
    monkeypatch.setattr(log_db, "recent_log_values", lambda kind: deepcopy((runtime.get("values") or {}).get(kind, [])))
    monkeypatch.setattr(log_db, "cost_for_log", lambda row: {
        "cost_ticks": int((row or {}).get("cost_ticks") or 0),
        "costed_success": 0, "unpriced_success": 0,
    })
    monkeypatch.setattr(oauth_manager, "list_accounts", lambda: deepcopy(runtime.get("accounts") or []))
    monkeypatch.setattr(oauth_manager, "_account_key", lambda account: account.get("account_key") or "")
    monkeypatch.setattr(ui, "channel_display_name", lambda key, with_family=False: str(key).split(":", 1)[-1])
    monkeypatch.setattr(ui, "channel_provider", lambda key: "")
    monkeypatch.setattr(ui, "channel_provider_custom_emoji_id", lambda key: None)
    monkeypatch.setattr(ui, "channel_provider_custom_emoji_html", lambda key: "")
    monkeypatch.setattr(logs_menu, "_maybe_suffix_status_banner", lambda text: text + runtime.get("suffix", ""))
    return capture, queries


def _short_state_final() -> dict[str, Any]:
    families: dict[str, int] = {}
    for value in ui._code_to_name.values():
        family = value.split(":", 1)[0] + ":" if ":" in value else "raw"
        families[family] = families.get(family, 0) + 1
    return {"registeredCodeCount": len(ui._code_to_name), "registeredCodeFamilies": families}


def _run_list(case, monkeypatch):
    capture, queries = _install(case, monkeypatch)
    entry = case["entry"]
    handled = None
    if entry["mode"] == "send":
        logs_menu.send_new(42)
    else:
        data = entry.get("callbackData", "menu:logs")
        if entry.get("dynamicListState") is not None:
            short = logs_menu._list_state_code(entry["dynamicListState"])
            data = f"logs:list:{short}"
        handled = logs_menu.handle_callback(42, 77, "cb-logs", data)
    final = {"handled": handled, "dbQueries": queries, **_short_state_final()}
    return actual_case(case, capture.calls, [], final)


def _run_query(case, monkeypatch):
    capture, queries = _install(case, monkeypatch)
    entry = case["entry"]
    short = logs_menu._list_state_code(entry["listState"]) if entry.get("valid", True) else "deadbeef"
    data = f"{entry['prefix']}{short}"
    handled = logs_menu.handle_callback(42, 77, "cb-query", data)
    return actual_case(case, capture.calls, [], {
        "handled": handled, "dbQueries": queries, **_short_state_final(),
    })


def _run_filter_open(case, monkeypatch):
    capture, queries = _install(case, monkeypatch)
    entry = case["entry"]
    short = logs_menu._list_state_code(entry["listState"])
    handled = logs_menu.handle_callback(
        42, 77, "cb-filter", f"logs:filter:{entry['kind']}:{short}",
    )
    return actual_case(case, capture.calls, [], {
        "handled": handled, "dbQueries": queries, **_short_state_final(),
    })


def _run_filter_transitions(case, monkeypatch):
    capture, queries = _install(case, monkeypatch)
    entry = case["entry"]
    kind = entry["kind"]
    base = deepcopy(entry["base"])
    draft = deepcopy(entry["draft"])
    state_short = logs_menu._filter_state_code(kind, base, draft)
    value_short = ui.register_code(entry["toggleValue"])
    callbacks = [
        f"logs:ftoggle:{kind}:{value_short}:{state_short}",
        f"logs:faction:{kind}:all:{state_short}",
        f"logs:faction:{kind}:invert:{state_short}",
        f"logs:faction:{kind}:confirm:{state_short}",
        f"logs:faction:{kind}:cancel:{state_short}",
    ]
    handled = [logs_menu.handle_callback(42, 77, f"cb-filter-{i}", data) for i, data in enumerate(callbacks, 1)]
    steps = [{"afterCallback": data.split(":", 3)[2], "callCount": i} for i, data in enumerate(callbacks, 1)]
    return actual_case(case, capture.calls, steps, {
        "handled": handled, "dbQueries": queries, **_short_state_final(),
    })


def _run_negative(case, monkeypatch):
    capture, queries = _install(case, monkeypatch)
    handled = logs_menu.handle_callback(42, 77, "cb-negative", case["entry"]["callbackData"])
    return actual_case(case, capture.calls, [], {
        "handled": handled, "dbQueries": queries, **_short_state_final(),
    })


RUNNERS = {
    "list": _run_list,
    "query": _run_query,
    "filter_open": _run_filter_open,
    "filter_transitions": _run_filter_transitions,
    "negative": _run_negative,
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["caseId"])
def test_logs_list_filter_trace(case, monkeypatch):
    ui._code_to_name.clear()
    actual = RUNNERS[case["entry"]["scenario"]](case, monkeypatch)
    assert_strict_equal(case, actual)


def test_logs_list_filter_case_ids_are_bidirectional():
    declared = {
        "TG-LOG-01.list-send-six-of-seven-status-protocol-transport-preview-banner",
        "TG-LOG-01.menu-list-page-one",
        "TG-LOG-01.page-two",
        "TG-LOG-01.refresh-invalid-page",
        "TG-LOG-01.short-list-filter-summary",
        "TG-LOG-02.query-menu",
        "TG-LOG-02.query-expired",
        "TG-LOG-02.query-clear",
        "TG-LOG-02.query-clear-expired",
        "TG-LOG-02.filter-apikey",
        "TG-LOG-02.filter-model",
        "TG-LOG-02.filter-channel",
        "TG-LOG-02.filter-status-negative",
        "TG-LOG-02.apikey-toggle-all-invert-confirm-cancel",
        "TG-LOG-02.model-toggle-all-invert-confirm-cancel",
        "TG-LOG-02.channel-toggle-all-invert-confirm-cancel",
        "TG-LOG-02.toggle-expired",
        "TG-LOG-02.action-malformed",
    }
    assert {case["caseId"] for case in CASES} == declared

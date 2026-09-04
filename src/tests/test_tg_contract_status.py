"""Executable, byte-strict v0.31.13 traces for TG-STATUS-01."""

from __future__ import annotations

from copy import deepcopy
import datetime as datetime_module
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from src.telegram import bot, menu_cache, states, ui
from src.telegram.menus import status_menu
from src.tests.tg_contract import TraceCapture, assert_strict_equal, load_jsonl


SEGMENT = Path(__file__).parent / "fixtures/tg_contract/v0.31.13/segments/main_status.jsonl"
CASES = load_jsonl(SEGMENT)
STATUS_CASES = [case for case in CASES if case["capabilityId"] == "TG-STATUS-01"]


def _actual(
    case: dict[str, Any],
    *,
    calls: list[dict[str, Any]],
    final: dict[str, Any],
    exception: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "caseId": case["caseId"],
        "capabilityId": case["capabilityId"],
        "entry": deepcopy(case["entry"]),
        "initialConfig": deepcopy(case["initialConfig"]),
        "initialState": deepcopy(case["initialState"]),
        "initialRuntime": deepcopy(case["initialRuntime"]),
        "tgApi": deepcopy(calls),
        "stateSteps": [],
        "finalBusinessState": deepcopy(final),
        "expectedException": deepcopy(exception),
    }


@pytest.fixture(autouse=True)
def _reset_globals():
    states.clear_all()
    menu_cache.reset_for_tests()
    ui.configure("fake-main-status-token", [42])
    ui._session = None
    yield
    states.clear_all()
    menu_cache.reset_for_tests()
    ui._session = None


def _patch_status(case: dict[str, Any], monkeypatch) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cfg = deepcopy(case["initialConfig"]["app"])
    runtime = case["initialRuntime"]
    events: list[dict[str, Any]] = []
    monkeypatch.setattr(status_menu.config, "get", lambda: cfg)
    monkeypatch.setattr(status_menu.time, "time", lambda: runtime["clock"])

    class FixedDateTime(datetime_module.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(runtime["clock"], tz)

    fake_datetime = ModuleType("datetime")
    for name in dir(datetime_module):
        setattr(fake_datetime, name, getattr(datetime_module, name))
    fake_datetime.datetime = FixedDateTime
    monkeypatch.setitem(sys.modules, "datetime", fake_datetime)
    monkeypatch.setattr(status_menu, "_SERVICE_START_TS", runtime["serviceStart"])
    monkeypatch.setattr(status_menu.affinity, "count", lambda: runtime.get("affinityCount", 0))
    monkeypatch.setattr(status_menu, "codex_cli_version", lambda: runtime.get("codexVersion", "0.0.0"))

    channels = [SimpleNamespace(**item) for item in runtime.get("registryChannels", [])]
    monkeypatch.setattr(status_menu.registry, "all_channels", lambda: channels)
    cooldown_entries = deepcopy(runtime.get("cooldownEntries") or [])
    monkeypatch.setattr(status_menu.cooldown, "active_entries", lambda: deepcopy(cooldown_entries))
    monkeypatch.setattr(
        status_menu.quota_errors,
        "active_quota_cooldown",
        lambda entry: entry.get("kind") == "quota",
    )
    monkeypatch.setattr(
        status_menu.quota_errors,
        "format_bjt_ms",
        lambda timestamp_ms, compact=False: runtime.get("quotaResetText", "01-02 03:04"),
    )

    monkeypatch.setattr(status_menu.scorer, "snapshot", lambda: deepcopy(runtime.get("scores") or []))
    monkeypatch.setattr(
        status_menu.ui,
        "channel_display_name",
        lambda key, with_family=True: (runtime.get("channelNames") or {}).get(key, key),
    )

    today = deepcopy(runtime.get("today") or {})
    bjt = datetime_module.timezone(datetime_module.timedelta(hours=8))
    now = datetime_module.datetime.fromtimestamp(runtime["clock"], bjt)
    today_since = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    monkeypatch.setattr(menu_cache, "today_start_ts", lambda: today_since)
    if not runtime.get("statsFailure"):
        menu_cache.PERIOD_STATS.store(("period", int(today_since)), {
            "summary": {"overall": deepcopy(today.get("total") or {})},
            "families": {
                family: {"overall": deepcopy(today.get(family) or {})}
                for family in ("anthropic", "openai")
            },
        })
    if not runtime.get("tpsFailure"):
        menu_cache.STATUS_TPS.store("month", {
            (item["channelKey"], item["model"]): item["tps"]
            for item in runtime.get("monthTps", [])
        })

    accounts = deepcopy(cfg.get("oauthAccounts") or [])
    monkeypatch.setattr(status_menu.oauth_manager, "list_accounts", lambda: deepcopy(accounts))
    quota_rows = deepcopy(runtime.get("quotaRows") or {})

    def quota_load(key):
        if runtime.get("quotaRefreshFailure"):
            raise RuntimeError("fake quota refresh failed")
        return deepcopy(quota_rows.get(key))

    monkeypatch.setattr(status_menu.state_db, "quota_load", quota_load)
    monkeypatch.setattr(
        status_menu.oauth_manager,
        "ensure_quota_fresh_sync",
        lambda _keys: pytest.fail("status compose must not refresh provider quota"),
    )
    monkeypatch.setattr(
        status_menu.oauth_manager,
        "fable_display_from_quota_row",
        lambda row: (row.get("fable_util"), row.get("fable_reset")),
    )
    monkeypatch.setattr(
        status_menu.oauth_manager,
        "usage_from_quota_row",
        lambda row: {"cursor": deepcopy(row.get("cursorUsage") or {})},
    )

    monkeypatch.setattr(
        status_menu.apikey_limiter,
        "totals",
        lambda: deepcopy(runtime.get("apiKeyTotals") or {
            "in_flight": 0, "waiting": 0, "tracked_keys": 0,
        }),
    )
    monkeypatch.setattr(
        status_menu.apikey_limiter,
        "snapshot",
        lambda: deepcopy(runtime.get("apiKeySnapshot") or []),
    )
    monkeypatch.setattr(
        status_menu.concurrency,
        "totals",
        lambda: deepcopy(runtime.get("concurrencyTotals") or {
            "in_flight": 0, "waiting": 0, "tracked_channels": 0,
        }),
    )
    monkeypatch.setattr(
        status_menu.concurrency,
        "snapshot",
        lambda: deepcopy(runtime.get("concurrencySnapshot") or []),
    )
    return cfg, events


def _exception_dict(exc: BaseException) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


def _run_status(case: dict[str, Any], monkeypatch) -> dict[str, Any]:
    capture = TraceCapture()
    monkeypatch.setattr(ui, "api", capture.api)
    cfg_before = deepcopy(case["initialConfig"].get("app") or {})
    cfg = cfg_before
    events: list[dict[str, Any]] = []
    scenario = case["entry"]["scenario"]
    handled: bool | None = None
    exception = None

    if scenario not in {"command_fallback", "unknown_callback"}:
        cfg, events = _patch_status(case, monkeypatch)
    try:
        if scenario == "command_fallback":
            bot._handle_update(deepcopy(case["entry"]["update"]))
        elif scenario == "send_new":
            status_menu.send_new(case["entry"]["chatId"])
        elif scenario in {"callback", "unknown_callback"}:
            handled = status_menu.handle_callback(
                case["entry"]["chatId"],
                case["entry"]["messageId"],
                case["entry"]["callbackId"],
                case["entry"]["data"],
            )
        else:  # pragma: no cover
            raise AssertionError(f"unknown status scenario: {scenario}")
    except Exception as exc:  # characterized failure behavior, never real network
        exception = _exception_dict(exc)

    return _actual(
        case,
        calls=capture.calls,
        final={
            "handled": handled,
            "configUnchanged": cfg == cfg_before,
            "chatState": states.get_state(case["entry"]["chatId"]),
            "runtimeEvents": events,
        },
        exception=exception,
    )


@pytest.mark.parametrize("case", STATUS_CASES, ids=lambda case: case["caseId"])
def test_status_trace(case, monkeypatch):
    # The v0.31.13 fixture records implementation-only synchronous query events.
    # Keep its Telegram bytes/state immutable while replacing those events with
    # cache reads, which are covered by the bounded-call regression below.
    expected = deepcopy(case)
    expected["finalBusinessState"]["runtimeEvents"] = []
    assert_strict_equal(expected, _run_status(case, monkeypatch))


def test_compose_only_reads_caches_and_one_concurrency_snapshot(monkeypatch):
    case = next(case for case in STATUS_CASES if case["caseId"].endswith("command-rich"))
    _patch_status(case, monkeypatch)
    counts = {
        "providerWait": 0,
        "statsSummary": 0,
        "monthTps": 0,
        "periodCacheRead": 0,
        "tpsCacheRead": 0,
        "concurrencySnapshot": 0,
    }

    def forbidden(name):
        def call(*_args, **_kwargs):
            import time
            counts[name] += 1
            time.sleep(0.2)
            raise AssertionError(f"synchronous {name} call from compose")
        return call

    monkeypatch.setattr(
        status_menu.oauth_manager, "ensure_quota_fresh_sync", forbidden("providerWait"),
    )
    monkeypatch.setattr(
        status_menu._CONTROL, "refresh_telegram_quota", forbidden("providerWait"),
    )
    monkeypatch.setattr(status_menu._CONTROL, "stats_summary", forbidden("statsSummary"))
    monkeypatch.setattr(status_menu._CONTROL, "tps_by_channel_model", forbidden("monthTps"))

    period_peek = menu_cache.PERIOD_STATS.peek
    tps_peek = menu_cache.STATUS_TPS.peek
    concurrency_snapshot = status_menu._CONTROL.concurrency_snapshot

    def counted_period_peek(key):
        counts["periodCacheRead"] += 1
        return period_peek(key)

    def counted_tps_peek(key):
        counts["tpsCacheRead"] += 1
        return tps_peek(key)

    def counted_concurrency_snapshot(context):
        counts["concurrencySnapshot"] += 1
        return concurrency_snapshot(context)

    monkeypatch.setattr(menu_cache.PERIOD_STATS, "peek", counted_period_peek)
    monkeypatch.setattr(menu_cache.STATUS_TPS, "peek", counted_tps_peek)
    monkeypatch.setattr(status_menu._CONTROL, "concurrency_snapshot", counted_concurrency_snapshot)

    import time
    started = time.perf_counter()
    text, keyboard = status_menu._compose()
    elapsed = time.perf_counter() - started

    expected_call = case["tgApi"][0]["payload"]
    assert text == expected_call["text"]
    assert keyboard == expected_call["reply_markup"]
    assert counts == {
        "providerWait": 0,
        "statsSummary": 0,
        "monthTps": 0,
        "periodCacheRead": 1,
        "tpsCacheRead": 1,
        "concurrencySnapshot": 1,
    }
    assert elapsed < 0.1

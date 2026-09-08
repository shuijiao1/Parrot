"""Exact-result and bounded-work contracts for management read optimizations."""
from __future__ import annotations

import os
import sqlite3
import threading
from collections import Counter
from contextlib import closing
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import log_db
from src.management_auth import Capability
from src.management_control.channels import ChannelControl
from src.tests.test_management_apikey_control import context, make_control
from src.tests.test_proxy_stats_cache import (
    BJT, CURRENT_TIME, OLD_TIME, _database, months,
)


def _seed(path, request_id, *, created=OLD_TIME, model="Straße", channel="api:a",
          api_key="k", status="success", latency=10, body=None):
    with closing(_database(path)) as conn:
        conn.execute(
            """INSERT INTO request_log(
                 request_id, created_at, api_key_name, requested_model, final_model,
                 final_channel_key, status, input_tokens, output_tokens,
                 connect_time_ms, first_token_time_ms, total_time_ms, is_stream,
                 ingress_protocol, upstream_protocol, usage_observed, error_message)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (request_id, created, api_key, model, model, channel, status, 20, 10,
             latency, latency*2, latency*4, 1, "chat", "openai-chat", 1, "needle"),
        )
        if body is not None:
            conn.execute(
                "INSERT INTO request_detail(request_id,response_body) VALUES(?,?)",
                (request_id, body),
            )
        conn.commit()


@pytest.fixture
def store(months):
    log_db._reset_lifetime_cache_for_tests()
    log_db._reset_summary_cache_for_tests()
    log_db._reset_filter_options_cache_for_tests()
    _seed(months.old, "old", latency=10)
    _seed(months.current, "current", created=CURRENT_TIME, latency=100)
    yield months
    log_db._reset_lifetime_cache_for_tests()
    log_db._reset_summary_cache_for_tests()
    log_db._reset_filter_options_cache_for_tests()


def _reader(kind):
    return {
        "lifetime": log_db.stats_lifetime,
        "summary": lambda: log_db.stats_period_snapshot(0),
        "filters": log_db.management_log_filter_options,
    }[kind]


def _probe(monkeypatch, kind):
    name = {
        "lifetime": "_aggregate_lifetime_month",
        "summary": "_aggregate_summary_month",
        "filters": "_management_filter_options_on_conn",
    }[kind]
    original = getattr(log_db, name)
    counts = Counter()
    lock = threading.Lock()

    def counted(conn, *args, **kwargs):
        month = Path(conn.execute("PRAGMA database_list").fetchone()[2]).name
        with lock:
            counts[month] += 1
        return original(conn, *args, **kwargs)

    monkeypatch.setattr(log_db, name, counted)
    return counts


@pytest.mark.parametrize("kind", ["lifetime", "summary", "filters"])
def test_sealed_cache_reuses_history_keeps_current_and_late_writes_fresh(store, monkeypatch, kind):
    read = _reader(kind)
    counts = _probe(monkeypatch, kind)
    first = read()
    assert first == read()
    assert counts == {"2026-08.db": 1, "2026-09.db": 2}
    first.clear()
    assert read(), "caller mutations cannot corrupt the cached raw facts"
    _seed(store.current, "current-new", created=CURRENT_TIME+1, model="fresh")
    current_changed = read()
    assert counts["2026-08.db"] == 1
    _seed(store.old, "old-new", model="late")
    assert read() != current_changed
    assert counts["2026-08.db"] == 2


@pytest.mark.parametrize("kind", ["lifetime", "summary", "filters"])
def test_wal_metadata_touch_is_not_commit_but_wal_commit_invalidates(store, monkeypatch, kind):
    read = _reader(kind)
    counts = _probe(monkeypatch, kind)
    with closing(sqlite3.connect(store.old)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE request_log SET input_tokens=input_tokens+1")
        writer.commit()
        first = read()
        wal = Path(str(store.old)+"-wal")
        assert wal.exists()
        os.chmod(wal, wal.stat().st_mode & 0o777)  # test-local metadata touch only
        assert read() == first
        assert counts["2026-08.db"] == 1
        writer.execute("UPDATE request_log SET api_key_name='late-key',input_tokens=input_tokens+1")
        writer.commit()
        assert read() != first
        assert counts["2026-08.db"] == 2


@pytest.mark.parametrize("kind", ["lifetime", "summary", "filters"])
def test_sealed_file_replacement_and_removal_invalidate(store, monkeypatch, kind):
    read = _reader(kind)
    counts = _probe(monkeypatch, kind)
    first = read()
    replacement = store.root / "replacement.tmp"
    _seed(replacement, "replacement", api_key="new-key", status="error", latency=80)
    os.replace(replacement, store.old)
    second = read()
    assert second != first
    assert counts["2026-08.db"] == 2
    store.old.unlink()
    assert read() != second
    cache = {
        "lifetime": log_db._lifetime_sealed_cache,
        "summary": log_db._summary_sealed_cache,
        "filters": log_db._filter_options_sealed_cache,
    }[kind]
    assert not cache


@pytest.mark.parametrize("kind", ["summary", "filters"])
def test_new_caches_singleflight_and_month_rollover(store, monkeypatch, kind):
    read = _reader(kind)
    counts = _probe(monkeypatch, kind)
    # Initialize local-only pricing/config before the concurrent query calls.
    log_db._lifetime_pricing_signature()
    barrier = threading.Barrier(4)
    results, errors = [], []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(read())
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert not errors
    assert len(results) == 4 and all(row == results[0] for row in results)
    assert counts["2026-08.db"] == 1
    assert counts["2026-09.db"] == 4
    store.clock["now"] = datetime(2026, 10, 2, 12, tzinfo=BJT)
    one = read()
    assert read() == one
    assert counts["2026-09.db"] == 5  # sealed only after crossing into October
    assert counts["2026-10.db"] == 2


@pytest.mark.parametrize("family", [None, "openai", "anthropic"])
@pytest.mark.parametrize("with_cost", [False, True])
def test_summary_raw_merge_cache_equals_live_for_all_shapes(store, monkeypatch, family, with_cost):
    _seed(store.old, "old-error", status="error", model="other", api_key="other", latency=70)
    _seed(store.current, "current-other", created=CURRENT_TIME+1, model="other", latency=30)
    kwargs = dict(family=family, include_cost=with_cost, include_family_slices=True)
    first = log_db.stats_summary(0, **kwargs)
    assert first == log_db.stats_summary(0, **kwargs)
    monkeypatch.setattr(log_db, "_summary_month", lambda conn, since, family, cost, groups, families, seen:
                        log_db._aggregate_summary_month(conn, since, family, cost, groups, families))
    assert first == log_db.stats_summary(0, **kwargs)
    if family is None:
        assert first["overall"]["total"] == 4
        assert first["overall"]["avg_connect_ms"] == pytest.approx(140/3)


def test_summary_cache_key_limits_shape_and_pricing_revision(store, monkeypatch):
    counts = _probe(monkeypatch, "summary")
    pricing = {"revision": "a"}
    monkeypatch.setattr(log_db, "_lifetime_pricing_signature", lambda: pricing["revision"])
    assert log_db.model_pricing.settings().enabled
    log_db.stats_summary(0, include_cost=True, summary_top_limit=0)
    log_db.stats_summary(0, include_cost=True, summary_top_limit=0)
    assert counts["2026-08.db"] == 1
    pricing["revision"] = "b"
    log_db.stats_summary(0, include_cost=True, summary_top_limit=0)
    assert counts["2026-08.db"] == 2
    log_db.stats_summary(0, include_cost=True, summary_top_limit=10)
    assert counts["2026-08.db"] == 3
    assert len(log_db._summary_sealed_cache) == 2
    # A moving window bypasses history caching rather than accumulating keys.
    log_db.stats_summary(OLD_TIME, include_cost=False)
    log_db.stats_summary(OLD_TIME+1, include_cost=False)
    assert counts["2026-08.db"] == 5
    assert len(log_db._summary_sealed_cache) == 2


@pytest.mark.parametrize("sort", ["createdAt", "status", "latency", "model"])
@pytest.mark.parametrize("descending", [False, True])
@pytest.mark.parametrize("cross_month", [False, True])
def test_light_search_full_rows_match_reference_paging_and_unicode(store, monkeypatch, sort, descending, cross_month):
    if not cross_month:
        store.old.unlink()
    for index in range(18):
        path = store.old if cross_month and index % 2 else store.current
        _seed(path, f"search-{index}", created=CURRENT_TIME + index//3,
              model="STRASSE" if index%3 else "unmatched",
              channel="oauth:xai:test" if index%2 else "api:a",
              status="error" if index%4 else "success", latency=index%4,
              body="display-only-body-" + "x"*1000)
    common = dict(sort=sort, descending=descending, statuses=["success","error"])
    candidates, _ = log_db.management_logs_page(**common, page_size=100)
    expected = [row for row in candidates if log_db._management_text_matches(row, "straße")]
    for page in (1, 2, 5):
        rows, count = log_db.management_logs_page(**common, query="straße", page=page, page_size=4)
        assert count == len(expected)
        assert rows == expected[(page-1)*4:page*4]


def test_text_search_never_loads_display_only_data_for_nonmatching_candidates(store, monkeypatch):
    _seed(store.current, "xai-no-match", created=CURRENT_TIME+1,
          channel="oauth:xai:test", body="body-only-query"*1000)
    statements = []
    original_open = log_db._open_readonly
    def traced(path):
        conn = original_open(path)
        conn.set_trace_callback(statements.append)
        return conn
    monkeypatch.setattr(log_db, "_open_readonly", traced)
    current = log_db._get_conn()
    current.set_trace_callback(statements.append)
    try:
        assert log_db.management_logs_page(query="body-only-query") == ([], 0)
    finally:
        current.set_trace_callback(None)
    selects = [sql for sql in statements if sql.lstrip().upper().startswith("SELECT") and "FROM request_log" in sql]
    assert selects
    assert all("request_detail" not in sql and "local_web_log" not in sql for sql in selects)
    assert all("LIMIT" not in sql for sql in selects)


def test_search_hydrates_selected_page_from_same_wal_snapshot(store, monkeypatch):
    store.old.unlink()
    _seed(store.current, "selected", created=CURRENT_TIME+1,
          channel="oauth:xai:test", body="old-body")
    writer = sqlite3.connect(store.current)
    original_match = log_db._management_text_matches
    changed = False
    def interleaved(row, query):
        nonlocal changed
        if not changed:
            changed = True
            writer.execute("UPDATE request_detail SET response_body='new-body' WHERE request_id='selected'")
            writer.execute("UPDATE request_log SET requested_model='changed' WHERE request_id='selected'")
            writer.commit()
        return original_match(row, query)
    monkeypatch.setattr(log_db, "_management_text_matches", interleaved)
    try:
        rows, total = log_db.management_logs_page(query="selected")
        assert total == 1
        assert rows[0]["response_body"] == "old-body"
        assert rows[0]["requested_model"] == "Straße"
        assert not log_db._get_conn().in_transaction
    finally:
        writer.close()


def test_key_and_channel_detail_never_compute_full_period_snapshot(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("single-object detail must not query the global monthly snapshot")
    control, _, _, _ = make_control()
    monkeypatch.setattr(control._stats, "stats_period_snapshot", forbidden)
    assert control.get_api_key(context(Capability.READ), "alpha").month_stats.total == 2
    channels = ChannelControl()
    monkeypatch.setattr(channels, "get_channel", lambda context, key: SimpleNamespace(id=key))
    monkeypatch.setattr(log_db, "stats_period_snapshot", forbidden)
    called = []
    def targeted(key, since):
        called.append((key, since))
        return {"total": 7}
    monkeypatch.setattr(log_db, "tokens_for_channel", targeted)
    monkeypatch.setattr(log_db, "channel_model_stats", lambda *args, **kwargs: [])
    assert channels.get_channel_detail(None, "api:test").month_stats.total == 7
    assert called[0][0] == "api:test"

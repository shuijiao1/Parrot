"""History-cache contracts; all databases and writes are test-local."""
from __future__ import annotations

import os
import sqlite3
import threading
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import log_db


BJT = timezone(timedelta(hours=8))
OLD_TIME = datetime(2026, 8, 15, 12, tzinfo=BJT).timestamp()
CURRENT_TIME = datetime(2026, 9, 7, 12, tzinfo=BJT).timestamp()


def _database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(log_db._schema_sql())
    log_db._ensure_migrations(conn)
    conn.commit()
    return conn


def _insert(conn, request_id, *, proxy="p1", created_at=OLD_TIME, tokens=10,
            latency=10, status="success", modern=True):
    round_id = f"round-{request_id}" if modern else None
    conn.execute(
        """INSERT INTO request_log (
             request_id, created_at, status, input_tokens, output_tokens,
             cache_creation_tokens, cache_read_tokens, proxy_name,
             proxy_bytes_up, proxy_bytes_down, connect_time_ms,
             first_token_time_ms, idle_time_ms, total_time_ms, final_round_id
           ) VALUES (?, ?, ?, ?, 2, 3, 4, ?, 10, 20, ?, ?, ?, ?, ?)""",
        (request_id, created_at, status, tokens, proxy, latency,
         latency * 2, latency // 2, latency * 3, round_id),
    )
    if modern:
        conn.execute(
            """INSERT INTO proxy_chain (
                 request_id, attempt_order, round_id, proxy_name, started_at,
                 outcome, connect_ms, first_byte_ms, idle_ms, total_ms,
                 bytes_up, bytes_down
               ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, 10, 20)""",
            (request_id, round_id, proxy, created_at,
             "success" if status == "success" else "idle_timeout",
             latency, latency * 2, latency // 2, latency * 3),
        )
    conn.commit()


def _seed(path, request_id, **kwargs):
    with closing(_database(path)) as conn:
        _insert(conn, request_id, **kwargs)


@pytest.fixture
def months(tmp_path, monkeypatch):
    root = tmp_path / "logs"
    root.mkdir()
    clock = {"now": datetime(2026, 9, 7, 12, tzinfo=BJT)}

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"].astimezone(tz) if tz else clock["now"].replace(tzinfo=None)

    registry = {}
    monkeypatch.setattr(log_db, "datetime", FixedDatetime)
    monkeypatch.setattr(log_db, "_log_dir", str(root))
    monkeypatch.setattr(log_db, "_local", threading.local())
    monkeypatch.setattr(log_db, "_write_conn_registry", registry)
    monkeypatch.setattr(log_db, "_retired_log_paths", set())
    log_db._reset_proxy_stats_cache_for_tests()
    yield SimpleNamespace(root=root, old=root / "2026-08.db", current=root / "2026-09.db", clock=clock)
    for connections in registry.values():
        for conn in connections:
            conn.close()
    log_db._reset_proxy_stats_cache_for_tests()


def _count_aggregates(monkeypatch):
    original = log_db._aggregate_proxy_month
    calls = Counter()
    lock = threading.Lock()

    def counted(conn, since):
        path = conn.execute("PRAGMA database_list").fetchone()[2]
        with lock:
            calls[Path(path).name] += 1
        return original(conn, since)

    monkeypatch.setattr(log_db, "_aggregate_proxy_month", counted)
    return calls


def test_proxy_cache_current_fresh_raw_sums_and_weighted_averages(months, monkeypatch):
    _seed(months.old, "old-modern", latency=10)
    _seed(months.old, "old-legacy", latency=10, modern=False)
    _seed(months.current, "current", created_at=CURRENT_TIME, latency=100)
    calls = _count_aggregates(monkeypatch)
    first = log_db.proxy_stats()
    assert first == log_db.proxy_stats()
    row = first[0]
    expected = {
        "requests": 3, "successes": 3, "failures": 0,
        "input_tokens": 30, "output_tokens": 6,
        "cache_creation_tokens": 9, "cache_read_tokens": 12, "total_tokens": 57,
        "bytes_up": 30, "bytes_down": 60, "total_bytes": 90,
        "connect_sum_ms": 120, "connect_sample_count": 3, "avg_connect_ms": 40,
        "first_byte_sum_ms": 240, "first_byte_sample_count": 3, "avg_first_byte_ms": 80,
        "idle_sum_ms": 60, "idle_sample_count": 3, "avg_idle_ms": 20,
        "total_sum_ms": 360, "total_sample_count": 3, "avg_total_ms": 120,
    }
    assert {key: row[key] for key in expected} == expected
    assert calls == {"2026-08.db": 1, "2026-09.db": 2}

    _seed(months.current, "current-new", created_at=CURRENT_TIME + 1,
          tokens=20, latency=70, status="error")
    fresh = log_db.proxy_stats()[0]
    assert (fresh["requests"], fresh["input_tokens"], fresh["failures"], fresh["avg_connect_ms"]) == (4, 50, 1, 47)
    fresh["input_tokens"] = -999
    assert log_db.proxy_stats()[0]["input_tokens"] == 50
    assert calls == {"2026-08.db": 1, "2026-09.db": 4}


def test_proxy_cache_limit_and_time_filters_do_not_pollute_full_history(months, monkeypatch):
    for i in range(2):
        _seed(months.old, f"old-a-{i}", proxy="a")
    _seed(months.old, "old-b", proxy="b")
    for i in range(3):
        _seed(months.current, f"current-c-{i}", proxy="c", created_at=CURRENT_TIME)
    calls = _count_aggregates(monkeypatch)
    assert [r["proxy_name"] for r in log_db.proxy_stats(limit=1)] == ["c"]
    full = log_db.proxy_stats(limit=20)
    assert [r["proxy_name"] for r in full] == ["c", "a", "b"]
    since = datetime(2026, 8, 20, tzinfo=BJT).timestamp()
    assert [r["proxy_name"] for r in log_db.proxy_stats(since_ts=since)] == ["c"]
    assert log_db.proxy_stats(since_ts=OLD_TIME - 1) == full
    assert log_db.proxy_stats(since_ts=0.0) == full
    assert calls == {"2026-08.db": 3, "2026-09.db": 5}
    assert len(log_db._proxy_stats_sealed_cache) == 1


def test_proxy_cache_invalidates_after_historical_late_write(months, monkeypatch):
    _seed(months.old, "old")
    _seed(months.current, "current", created_at=CURRENT_TIME)
    calls = _count_aggregates(monkeypatch)
    assert log_db.proxy_stats()[0]["requests"] == 2
    _seed(months.old, "late", tokens=20)
    assert log_db.proxy_stats()[0]["input_tokens"] == 40
    assert log_db.proxy_stats()[0]["requests"] == 3
    assert calls == {"2026-08.db": 2, "2026-09.db": 3}


def test_proxy_cache_invalidates_wal_commit_without_main_file_change(months, monkeypatch):
    with closing(_database(months.old)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        _insert(writer, "old")
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        _seed(months.current, "current", created_at=CURRENT_TIME)
        calls = _count_aggregates(monkeypatch)
        assert log_db.proxy_stats()[0]["input_tokens"] == 20
        assert log_db.proxy_stats()[0]["input_tokens"] == 20
        assert calls == {"2026-08.db": 1, "2026-09.db": 2}
        before = months.old.stat()
        writer.execute("UPDATE request_log SET input_tokens=77 WHERE request_id='old'")
        writer.commit()
        after = months.old.stat()
        assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
        assert log_db.proxy_stats()[0]["input_tokens"] == 87
        assert log_db.proxy_stats()[0]["input_tokens"] == 87
        assert calls == {"2026-08.db": 2, "2026-09.db": 4}


@pytest.mark.parametrize("change", ["replace", "delete", "incompatible-schema"])
def test_proxy_cache_file_changes_never_return_old_cache(months, monkeypatch, change):
    _seed(months.old, "old")
    _seed(months.current, "current", created_at=CURRENT_TIME)
    calls = _count_aggregates(monkeypatch)
    assert log_db.proxy_stats()[0]["requests"] == 2
    if change == "replace":
        replacement = months.root / "replacement.sqlite"
        _seed(replacement, "replacement", tokens=99)
        os.replace(replacement, months.old)
        assert log_db.proxy_stats()[0]["input_tokens"] == 109
        assert calls["2026-08.db"] == 2
    elif change == "delete":
        months.old.unlink()
        assert log_db.proxy_stats()[0]["requests"] == 1
        assert str(months.old.resolve()) not in log_db._proxy_stats_sealed_cache
    else:
        with sqlite3.connect(months.old) as writer:
            writer.execute("ALTER TABLE request_log RENAME TO incompatible_request_log")
        with pytest.raises(log_db.HistoricalLogError):
            log_db.proxy_stats()


def test_proxy_cache_does_not_store_snapshot_changed_during_aggregation(months, monkeypatch):
    _seed(months.old, "old")
    _seed(months.current, "current", created_at=CURRENT_TIME)
    original = log_db._aggregate_proxy_month
    old_calls = []

    def late_write(conn, since):
        rows = original(conn, since)
        path = conn.execute("PRAGMA database_list").fetchone()[2]
        if path == str(months.old):
            old_calls.append(1)
            if len(old_calls) == 1:
                _seed(months.old, "late", tokens=20)
        return rows

    monkeypatch.setattr(log_db, "_aggregate_proxy_month", late_write)
    assert log_db.proxy_stats()[0]["requests"] == 2
    assert str(months.old) not in log_db._proxy_stats_sealed_cache
    assert log_db.proxy_stats()[0]["requests"] == 3
    assert log_db.proxy_stats()[0]["requests"] == 3
    assert len(old_calls) == 2


def test_proxy_cache_replacement_during_open_does_not_mislabel_old_connection(months, monkeypatch):
    _seed(months.old, "old")
    _seed(months.current, "current", created_at=CURRENT_TIME)
    replacement = months.root / "replacement.sqlite"
    _seed(replacement, "new-file", tokens=99)
    original = log_db._open_readonly
    opens = []

    def replace_during_open(path):
        conn = original(path)
        if path == str(months.old):
            opens.append(1)
            # First open belongs to the unchanged month iterator; the second is
            # the cache's own connection after its pre-open file fingerprint.
            if len(opens) == 2:
                os.replace(replacement, months.old)
        return conn

    monkeypatch.setattr(log_db, "_open_readonly", replace_during_open)
    log_db.proxy_stats()
    assert str(months.old) not in log_db._proxy_stats_sealed_cache
    assert log_db.proxy_stats()[0]["input_tokens"] == 109
    assert log_db.proxy_stats()[0]["input_tokens"] == 109


def test_proxy_cache_history_singleflight_across_concurrent_calls(months, monkeypatch):
    _seed(months.old, "old")
    _seed(months.current, "current", created_at=CURRENT_TIME)
    calls = _count_aggregates(monkeypatch)
    barrier = threading.Barrier(4)
    results, errors = [], []

    def run():
        try:
            barrier.wait(timeout=10)
            results.append(log_db.proxy_stats())
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert all(not thread.is_alive() for thread in threads)
    assert not errors
    assert len(results) == 4 and all(value == results[0] for value in results)
    assert calls == {"2026-08.db": 1, "2026-09.db": 4}


def test_proxy_cache_month_rollover_keeps_new_current_fresh(months, monkeypatch):
    _seed(months.old, "old")
    _seed(months.current, "september", created_at=CURRENT_TIME)
    october = months.root / "2026-10.db"
    october_time = datetime(2026, 10, 1, 1, tzinfo=BJT).timestamp()
    _seed(october, "october", created_at=october_time)
    calls = _count_aggregates(monkeypatch)
    assert log_db.proxy_stats()[0]["requests"] == 2
    months.clock["now"] = datetime(2026, 10, 1, 12, tzinfo=BJT)
    assert log_db.proxy_stats()[0]["requests"] == 3
    _seed(october, "october-new", created_at=october_time + 1)
    assert log_db.proxy_stats()[0]["requests"] == 4
    assert calls == {"2026-08.db": 1, "2026-09.db": 2, "2026-10.db": 2}
    _seed(months.current, "september-late", created_at=CURRENT_TIME + 1)
    assert log_db.proxy_stats()[0]["requests"] == 5
    assert calls["2026-09.db"] == 3


def test_proxy_cache_log_directory_identity_and_cleanup(months, monkeypatch, tmp_path):
    _seed(months.old, "old")
    _seed(months.current, "current", created_at=CURRENT_TIME)
    assert log_db.proxy_stats()[0]["input_tokens"] == 20
    other = tmp_path / "other-logs"
    _seed(other / "2026-08.db", "other-old", tokens=99)
    monkeypatch.setattr(log_db, "_log_dir", str(other))
    assert log_db.proxy_stats()[0]["input_tokens"] == 99
    assert set(log_db._proxy_stats_sealed_cache) == {str(other / "2026-08.db")}

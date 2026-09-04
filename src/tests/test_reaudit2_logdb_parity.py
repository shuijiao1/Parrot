from __future__ import annotations

import heapq
import sqlite3
from typing import Any

import pytest

from src import log_db


_INT64_SAFE_LARGE = 5_000_000_000_000_000_000
_EXACT_PAIR_TOTAL = 10_000_000_000_000_000_000


def _memory_log_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(log_db._schema_sql())
    return conn


def _insert_request(
    conn: sqlite3.Connection,
    request_id: str,
    *,
    created_at: float = 100.0,
    status: str = "success",
    api_key: str = "k",
    model: str = "m",
    channel: str = "c",
    protocol: str = "chat",
    total_ms: int = 7,
    token_value: int = 0,
    error_message: str | None = "Needle",
) -> None:
    conn.execute(
        """INSERT INTO request_log(
               request_id, created_at, status, api_key_name, requested_model,
               final_model, final_channel_key, ingress_protocol,
               upstream_protocol, total_time_ms, error_message,
               input_tokens, output_tokens, cache_creation_tokens,
               cache_read_tokens, usage_observed)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            request_id,
            created_at,
            status,
            api_key,
            model,
            model,
            channel,
            protocol,
            "openai-chat",
            total_ms,
            error_message,
            token_value,
            token_value,
            token_value,
            token_value,
            1,
        ),
    )


def _insert_attempt(
    conn: sqlite3.Connection,
    retry_id: int,
    root_request_id: str,
    *,
    token_value: int,
) -> None:
    conn.execute(
        """INSERT INTO upstream_attempt_usage(
               retry_attempt_id, root_request_id, call_request_id,
               attempt_order, channel_key, channel_type, model, outcome,
               usage_observed, input_tokens, output_tokens,
               cache_creation_tokens, cache_read_tokens, service_tier,
               upstream_protocol, cost_source, settled_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            retry_id,
            root_request_id,
            root_request_id,
            retry_id,
            "c",
            "api",
            "m",
            "success",
            1,
            token_value,
            token_value,
            token_value,
            token_value,
            "standard",
            "openai-chat",
            "unpriced",
            100.0,
        ),
    )


def _assert_token_totals(summary: dict[str, Any], expected: int) -> None:
    overall = summary["overall"]
    for field in (
        "total_input_tokens",
        "total_output_tokens",
        "total_cache_creation",
        "total_cache_read",
    ):
        assert overall[field] == expected
        assert type(overall[field]) is int

    for dimension in ("by_channel", "by_model", "by_apikey"):
        metrics = summary[dimension][0]["metrics"]
        assert metrics["total_prompt_tokens"] == expected * 3
        assert metrics["total_output_tokens"] == expected
        assert metrics["total_cache_creation"] == expected
        assert metrics["total_cache_read"] == expected
        for field in (
            "total_prompt_tokens",
            "total_output_tokens",
            "total_cache_creation",
            "total_cache_read",
        ):
            assert type(metrics[field]) is int


def test_stats_summary_attempt_token_overflow_is_exact_and_fast_path_stays_native(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _memory_log_db()
    _insert_request(conn, "root")
    _insert_attempt(conn, 1, "root", token_value=_INT64_SAFE_LARGE)
    _insert_attempt(conn, 2, "root", token_value=_INT64_SAFE_LARGE)
    conn.commit()
    monkeypatch.setattr(
        log_db, "_iter_month_conns", lambda _since: [(conn, lambda: None)],
    )

    statements: list[str] = []
    conn.set_trace_callback(statements.append)
    summary = log_db.stats_summary(0, include_cost=False, summary_top_limit=10)
    _assert_token_totals(summary, _EXACT_PAIR_TOTAL)
    assert any(log_db._EXACT_INT_SUM_FUNCTION in sql for sql in statements)

    conn.execute(
        """UPDATE upstream_attempt_usage
              SET input_tokens=2, output_tokens=2,
                  cache_creation_tokens=2, cache_read_tokens=2"""
    )
    conn.commit()
    statements.clear()
    normal = log_db.stats_summary(0, include_cost=False, summary_top_limit=10)
    _assert_token_totals(normal, 4)
    assert any("SUM(a.input_tokens)" in sql for sql in statements)
    assert all(log_db._EXACT_INT_SUM_FUNCTION not in sql for sql in statements)
    conn.close()


def test_summary_root_token_replacement_uses_exact_group_totals() -> None:
    conn = _memory_log_db()
    for index in (1, 2):
        request_id = f"root-{index}"
        _insert_request(conn, request_id, token_value=_INT64_SAFE_LARGE)
        _insert_attempt(conn, index, request_id, token_value=1)
    conn.commit()

    overall = log_db._new_overall_agg()
    overall.update(
        total_input_tokens=_EXACT_PAIR_TOTAL,
        total_output_tokens=_EXACT_PAIR_TOTAL,
        total_cache_creation=_EXACT_PAIR_TOTAL,
        total_cache_read=_EXACT_PAIR_TOTAL,
        success_with_cache_write=2,
        success_with_cache_hit=2,
    )

    def seeded_group() -> dict[str, Any]:
        bucket = log_db._new_group_agg()
        bucket.update(
            total_prompt_tokens=_EXACT_PAIR_TOTAL * 3,
            total_output_tokens=_EXACT_PAIR_TOTAL,
            total_cache_creation=_EXACT_PAIR_TOTAL,
            total_cache_read=_EXACT_PAIR_TOTAL,
            write_requests=2,
            hit_requests=2,
        )
        return bucket

    by_channel = {"c": seeded_group()}
    by_model = {"m": seeded_group()}
    by_apikey = {"k": seeded_group()}
    statements: list[str] = []
    conn.set_trace_callback(statements.append)

    log_db._replace_summary_tokens_with_attempts(
        conn, 0, None, overall, by_channel, by_model, by_apikey,
    )

    for field in (
        "total_input_tokens",
        "total_output_tokens",
        "total_cache_creation",
        "total_cache_read",
    ):
        assert overall[field] == 2
        assert type(overall[field]) is int
    for bucket in (by_channel["c"], by_model["m"], by_apikey["k"]):
        assert bucket["total_prompt_tokens"] == 6
        assert bucket["total_output_tokens"] == 2
        assert bucket["total_cache_creation"] == 2
        assert bucket["total_cache_read"] == 2
    assert any(log_db._EXACT_INT_SUM_FUNCTION in sql for sql in statements)
    conn.close()


def _insert_tie_rows(conn: sqlite3.Connection) -> None:
    for index in range(1, 7):
        _insert_request(conn, f"r{index}")
    conn.commit()


def _frozen_selector_ids(
    conn: sqlite3.Connection,
    *,
    sort: str = "createdAt",
    descending: bool = True,
    page: int = 1,
    page_size: int = 2,
    statuses: list[str] | None = None,
    api_keys: list[str] | None = None,
    models: list[str] | None = None,
    channel_keys: list[str] | None = None,
    protocols: list[str] | None = None,
    query: str | None = None,
    started_at: float | None = None,
    ended_at: float | None = None,
) -> tuple[list[str], int]:
    """Run the pre-pushdown selector over its real SQLite candidate query."""

    pushed_status = statuses[0] if statuses and len(statuses) == 1 else None
    where, values = log_db._recent_logs_where(
        status=pushed_status,
        api_keys=api_keys,
        models=models,
        channel_keys=channel_keys,
    )
    candidates = [
        dict(row)
        for row in conn.execute(
            f"SELECT * FROM request_log {where} ORDER BY created_at DESC",
            values,
        )
    ]
    status_set = set(statuses or [])
    protocol_set = set(protocols or [])
    needle = query.casefold() if query else None

    def matches(row: dict[str, Any]) -> bool:
        if len(status_set) > 1 and str(row.get("status") or "") not in status_set:
            return False
        if protocol_set and str(row.get("ingress_protocol") or "") not in protocol_set:
            return False
        created_at = float(row.get("created_at") or 0)
        if started_at is not None and created_at < started_at:
            return False
        if ended_at is not None and created_at > ended_at:
            return False
        if needle is not None:
            fields = (
                "request_id",
                "requested_model",
                "final_model",
                "final_channel_key",
                "api_key_name",
                "error_message",
            )
            if not any(
                needle in str(row.get(field) or "").casefold() for field in fields
            ):
                return False
        return True

    matched = [row for row in candidates if matches(row)]

    def sort_value(row: dict[str, Any]) -> Any:
        if sort == "status":
            return str(row.get("status") or "")
        if sort == "latency":
            return float(row.get("total_time_ms") or 0)
        if sort == "model":
            return str(
                row.get("requested_model") or row.get("final_model") or ""
            ).casefold()
        return float(row.get("created_at") or 0)

    top_k = page * page_size
    selector = heapq.nlargest if descending else heapq.nsmallest
    selected = selector(top_k, matched, key=sort_value)
    start = (page - 1) * page_size
    return [row["request_id"] for row in selected[start:start + page_size]], len(matched)


def _assert_pages_match_frozen(
    conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    **kwargs: Any,
) -> list[str]:
    monkeypatch.setattr(log_db, "_get_conn", lambda: conn)
    actual_all: list[str] = []
    expected_all: list[str] = []
    for page in (1, 2, 3):
        actual, total = log_db.management_logs_page(
            page=page, page_size=2, **kwargs,
        )
        expected, expected_total = _frozen_selector_ids(
            conn, page=page, page_size=2, **kwargs,
        )
        assert total == expected_total == 6
        actual_ids = [row["request_id"] for row in actual]
        assert actual_ids == expected
        actual_all.extend(actual_ids)
        expected_all.extend(expected)
    assert actual_all == expected_all
    return actual_all


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({}, ["r6", "r5", "r4", "r3", "r2", "r1"]),
        ({"statuses": ["success"]}, ["r1", "r2", "r3", "r4", "r5", "r6"]),
        ({"api_keys": ["k"]}, ["r1", "r2", "r3", "r4", "r5", "r6"]),
        ({"channel_keys": ["c"]}, ["r1", "r2", "r3", "r4", "r5", "r6"]),
        ({"models": ["m"]}, ["r6", "r5", "r4", "r3", "r2", "r1"]),
        ({"protocols": ["chat"]}, ["r6", "r5", "r4", "r3", "r2", "r1"]),
    ],
)
def test_management_default_tie_pages_match_frozen_candidate_scan(
    monkeypatch: pytest.MonkeyPatch,
    filters: dict[str, Any],
    expected: list[str],
) -> None:
    conn = _memory_log_db()
    _insert_tie_rows(conn)
    assert _assert_pages_match_frozen(conn, monkeypatch, **filters) == expected
    conn.close()


@pytest.mark.parametrize("sort", ["createdAt", "status", "latency", "model"])
@pytest.mark.parametrize("descending", [False, True])
@pytest.mark.parametrize(
    "filters",
    [{}, {"statuses": ["success"]}],
    ids=["unfiltered", "status-filtered"],
)
def test_management_all_sort_directions_preserve_frozen_ties(
    monkeypatch: pytest.MonkeyPatch,
    sort: str,
    descending: bool,
    filters: dict[str, Any],
) -> None:
    conn = _memory_log_db()
    _insert_tie_rows(conn)
    _assert_pages_match_frozen(
        conn, monkeypatch, sort=sort, descending=descending, **filters,
    )
    conn.close()


@pytest.mark.parametrize(
    "filters",
    [
        {"query": "needle"},
        {"statuses": ["success"], "query": "needle"},
    ],
    ids=["unfiltered-candidates", "status-filtered-candidates"],
)
def test_management_text_path_preserves_frozen_ties_and_page_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    filters: dict[str, Any],
) -> None:
    conn = _memory_log_db()
    _insert_tie_rows(conn)
    _assert_pages_match_frozen(
        conn,
        monkeypatch,
        sort="model",
        descending=False,
        **filters,
    )
    conn.close()

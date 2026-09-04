from __future__ import annotations

import itertools
import sqlite3
from typing import Any

import pytest

from src import log_db


def _memory_log_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(log_db._schema_sql())
    return conn


def _insert_request(
    conn: sqlite3.Connection,
    request_id: str,
    *,
    status: str = "success",
    api_key: str = "k",
    model: str = "m",
    channel: str = "c",
) -> None:
    conn.execute(
        """INSERT INTO request_log(
               request_id, created_at, status, api_key_name, requested_model,
               final_model, final_channel_key, ingress_protocol, total_time_ms)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (request_id, 100.0, status, api_key, model, model, channel, "chat", 7),
    )


def _frozen_where(
    *,
    statuses: list[str] | None = None,
    api_keys: list[str] | None = None,
    models: list[str] | None = None,
    channel_keys: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Exact structured pushdown used by the pre-SQL Management selector."""

    conditions: list[str] = []
    values: list[str] = []
    clean_statuses = [str(value) for value in (statuses or []) if str(value)]
    if len(clean_statuses) == 1:
        conditions.append("status=?")
        values.append(clean_statuses[0])
    clean_keys = [str(value) for value in (api_keys or []) if str(value)]
    if clean_keys:
        conditions.append(
            "api_key_name IN (" + ",".join("?" for _ in clean_keys) + ")"
        )
        values.extend(clean_keys)
    clean_models = [str(value) for value in (models or []) if str(value)]
    if clean_models:
        placeholders = ",".join("?" for _ in clean_models)
        conditions.append(
            f"(requested_model IN ({placeholders}) OR final_model IN ({placeholders}))"
        )
        values.extend(clean_models)
        values.extend(clean_models)
    clean_channels = [str(value) for value in (channel_keys or []) if str(value)]
    if clean_channels:
        conditions.append(
            "final_channel_key IN ("
            + ",".join("?" for _ in clean_channels)
            + ")"
        )
        values.extend(clean_channels)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    return where, values


def _frozen_default_ids(
    conn: sqlite3.Connection,
    **filters: Any,
) -> list[str]:
    where, values = _frozen_where(**filters)
    rows = conn.execute(
        f"SELECT request_id, status FROM request_log {where} "
        "ORDER BY created_at DESC",
        values,
    ).fetchall()
    statuses = {str(value) for value in (filters.get("statuses") or []) if str(value)}
    if len(statuses) > 1:
        rows = [row for row in rows if str(row["status"] or "") in statuses]
    return [str(row["request_id"]) for row in rows]


def test_single_api_multi_channel_pages_match_frozen_candidate_order(
    monkeypatch,
) -> None:
    conn = _memory_log_db()
    for index, (channel, model) in enumerate(
        zip(("y", "x", "y", "x", "y", "x"), ("m2", "m1") * 3),
        start=1,
    ):
        _insert_request(conn, f"r{index}", api_key="k", channel=channel, model=model)
    conn.commit()
    monkeypatch.setattr(log_db, "_get_conn", lambda: conn)
    filters = {
        "api_keys": ["k"],
        "models": ["m1", "m2"],
        "channel_keys": ["x", "y"],
    }

    where, values = _frozen_where(**filters)
    plan = [
        str(row["detail"])
        for row in conn.execute(
            f"EXPLAIN QUERY PLAN SELECT request_id FROM request_log {where} "
            "ORDER BY created_at DESC",
            values,
        )
    ]
    assert any("USING INDEX idx_log_apikey" in detail for detail in plan)
    assert any("USE TEMP B-TREE FOR ORDER BY" in detail for detail in plan)

    frozen_ids = _frozen_default_ids(conn, **filters)
    expected_pages = [["r1", "r2"], ["r3", "r4"], ["r5", "r6"]]
    assert frozen_ids == [request_id for page in expected_pages for request_id in page]
    for page_number, expected in enumerate(expected_pages, start=1):
        rows, total = log_db.management_logs_page(
            **filters, page=page_number, page_size=2,
        )
        assert total == 6
        assert [str(row["request_id"]) for row in rows] == expected
        assert [str(row["request_id"]) for row in rows] == frozen_ids[
            (page_number - 1) * 2:page_number * 2
        ]
    conn.close()


@pytest.mark.parametrize("sort", ["status", "latency", "model"])
@pytest.mark.parametrize("descending", [False, True])
def test_combination_candidate_order_is_stable_for_other_public_sort_ties(
    monkeypatch,
    sort: str,
    descending: bool,
) -> None:
    conn = _memory_log_db()
    for index, channel in enumerate(("y", "x", "y", "x", "y", "x"), start=1):
        _insert_request(conn, f"r{index}", api_key="k", channel=channel)
    conn.commit()
    monkeypatch.setattr(log_db, "_get_conn", lambda: conn)
    filters = {"api_keys": ["k"], "channel_keys": ["x", "y"]}
    frozen_ids = _frozen_default_ids(conn, **filters)

    actual_ids: list[str] = []
    for page_number in (1, 2, 3):
        rows, total = log_db.management_logs_page(
            **filters,
            sort=sort,
            descending=descending,
            page=page_number,
            page_size=2,
        )
        assert total == 6
        actual_ids.extend(str(row["request_id"]) for row in rows)
    assert actual_ids == frozen_ids == ["r1", "r2", "r3", "r4", "r5", "r6"]
    conn.close()


def test_candidate_tie_order_matches_frozen_sqlite_plan_for_filter_combinations() -> None:
    conn = _memory_log_db()
    statuses_options = (None, ["success"], ["success", "error"])
    api_key_options = (None, ["a"], ["a", "b"])
    model_options = (None, ["m1", "m2"])
    channel_options = (None, ["x"], ["x", "y"])
    order_for_index = {
        "idx_log_created": "id DESC",
        "idx_log_status": "status ASC, id ASC",
        "idx_log_apikey": "api_key_name ASC, id ASC",
        "idx_log_channel": "final_channel_key ASC, id ASC",
    }

    for statuses, api_keys, models, channel_keys in itertools.product(
        statuses_options, api_key_options, model_options, channel_options,
    ):
        filters = {
            "statuses": statuses,
            "api_keys": api_keys,
            "models": models,
            "channel_keys": channel_keys,
        }
        where, values = _frozen_where(**filters)
        plan = " | ".join(
            str(row["detail"])
            for row in conn.execute(
                f"EXPLAIN QUERY PLAN SELECT id FROM request_log {where} "
                "ORDER BY created_at DESC",
                values,
            )
        )
        selected = [
            order for index, order in order_for_index.items() if index in plan
        ]
        assert len(selected) == 1, (filters, plan)
        assert log_db._management_candidate_tie_order(
            statuses=statuses,
            api_keys=api_keys,
            channel_keys=channel_keys,
        ) == selected[0], (filters, plan)
    conn.close()

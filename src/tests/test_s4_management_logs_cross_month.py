from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta

import pytest

from src import log_db
from src.management_auth import AuthMethod, Capability
from src.management_control.observability import LogsControl
from src.tests.management_observability_support import build_client, fake_controls


@pytest.fixture
def monthly_log_store(monkeypatch, tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr(log_db, "_log_dir", str(log_dir))
    monkeypatch.setattr(log_db, "_initialized", True)
    monkeypatch.setattr(log_db, "_local", threading.local())
    monkeypatch.setattr(log_db, "_write_conn_registry", {})
    monkeypatch.setattr(log_db, "_retired_log_paths", set())

    # The Management path must find history even while the real current store is empty.
    log_db._get_conn()
    current_start = datetime.now(log_db._BJT).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0,
    )
    previous_end = current_start - timedelta(seconds=1)
    previous_start = previous_end.replace(day=1, hour=0, minute=0, second=0)
    older_end = previous_start - timedelta(seconds=1)
    older_start = older_end.replace(day=1, hour=0, minute=0, second=0)

    yield {
        "dir": log_dir,
        "current": current_start,
        "newer": previous_start,
        "older": older_start,
    }

    for connections in list(log_db._write_conn_registry.values()):
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def _month_path(store, start: datetime) -> str:
    return str(store["dir"] / f"{start.strftime('%Y-%m')}.db")


def _create_month(store, start: datetime, rows: list[dict]) -> None:
    conn = sqlite3.connect(_month_path(store, start))
    try:
        conn.executescript(log_db._schema_sql())
        for row in rows:
            conn.execute(
                """INSERT INTO request_log(
                       request_id, created_at, status, api_key_name,
                       requested_model, final_model, final_channel_key,
                       ingress_protocol, total_time_ms, input_tokens,
                       output_tokens, error_message)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["id"], row["created_at"], row.get("status", "success"),
                    row.get("api_key", "shared-key"), row.get("model", "shared-model"),
                    row.get("final_model", row.get("model", "shared-model")),
                    row.get("channel", "api:shared"), row.get("protocol", "chat"),
                    row.get("latency", 0), row.get("input_tokens", 0),
                    row.get("output_tokens", 0), row.get("error"),
                ),
            )
            if "request_body" in row or "response_body" in row or "headers" in row:
                conn.execute(
                    """INSERT INTO request_detail(
                           request_id, request_headers, request_body, response_body)
                       VALUES(?,?,?,?)""",
                    (
                        row["id"], row.get("headers"), row.get("request_body"),
                        row.get("response_body"),
                    ),
                )
        conn.commit()
    finally:
        conn.close()


def _install_historical_rows(store) -> dict[str, object]:
    encrypted = "encrypted-payload-" + "x" * 180
    request_body = {
        "token": "business-token",
        "api_key": "business-api-key",
        "password": "business-password",
        "encrypted_content": encrypted,
        "messages": [{"role": "user", "content": "BODY-NEEDLE keep"}],
    }
    response_body = {
        "token": "response-token",
        "api_key": "response-api-key",
        "password": "response-password",
        "result": "BODY-NEEDLE response",
    }
    newer = store["newer"]
    older = store["older"]
    _create_month(store, newer, [
        {
            "id": "new-low", "created_at": (newer + timedelta(days=20)).timestamp(),
            "latency": 10,
        },
        {
            "id": "historic-body", "created_at": (newer + timedelta(days=10)).timestamp(),
            "status": "error", "api_key": "body-key", "model": "body-model",
            "channel": "api:body", "latency": 40,
            "input_tokens": 9_000_000_000_000_000_000,
            "error": "BODY-NEEDLE failure",
            "headers": json.dumps({"Authorization": "Bearer header-secret"}),
            "request_body": json.dumps(request_body, ensure_ascii=False),
            "response_body": json.dumps(response_body, ensure_ascii=False),
        },
    ])
    _create_month(store, older, [
        {
            "id": "old-high", "created_at": (older + timedelta(days=20)).timestamp(),
            "latency": 90,
        },
        {
            "id": "old-mid", "created_at": (older + timedelta(days=10)).timestamp(),
            "latency": 30, "protocol": "anthropic",
        },
    ])

    # Valid SQLite files outside the strict YYYY-MM.db bundle must never participate.
    unrelated_path = store["dir"] / "unrelated.db"
    conn = sqlite3.connect(unrelated_path)
    try:
        conn.executescript(log_db._schema_sql())
        conn.execute(
            "INSERT INTO request_log(request_id,created_at) VALUES('ignored-unrelated',?)",
            (older.timestamp(),),
        )
        conn.commit()
    finally:
        conn.close()
    conn = sqlite3.connect(store["dir"] / "2026-13.db")
    try:
        conn.executescript(log_db._schema_sql())
        conn.execute(
            "INSERT INTO request_log(request_id,created_at) VALUES('ignored-invalid-month',?)",
            (older.timestamp(),),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "request": request_body,
        "response": response_body,
        "encrypted": encrypted,
    }


def test_management_log_db_cross_month_global_page_count_options_and_tg_isolation(
    monthly_log_store,
):
    _install_historical_rows(monthly_log_store)

    # Frozen TG primitives stay current-month-only.
    assert log_db.recent_logs_count() == 0
    assert log_db.recent_logs(limit=20) == []
    assert log_db.log_detail("historic-body")["log"] is None

    first, total = log_db.management_logs_page(
        sort="latency", descending=True, page=1, page_size=2,
    )
    second, second_total = log_db.management_logs_page(
        sort="latency", descending=True, page=2, page_size=2,
    )
    assert total == second_total == 4
    assert [row["request_id"] for row in first] == ["old-high", "historic-body"]
    assert [row["request_id"] for row in second] == ["old-mid", "new-low"]

    # All success rows have the same primary status key; the existing created-at
    # secondary order remains stable across the global page boundary.
    tied_first, tied_total = log_db.management_logs_page(
        statuses=["success"], sort="status", descending=False, page=1, page_size=2,
    )
    tied_second, _ = log_db.management_logs_page(
        statuses=["success"], sort="status", descending=False, page=2, page_size=2,
    )
    assert tied_total == 3
    assert [row["request_id"] for row in tied_first + tied_second] == [
        "new-low", "old-high", "old-mid",
    ]

    filtered, filtered_total = log_db.management_logs_page(
        api_keys=["body-key"], models=["body-model"], channel_keys=["api:body"],
        protocols=["chat"], query="body-needle", page=1, page_size=10,
    )
    assert filtered_total == 1
    assert [row["request_id"] for row in filtered] == ["historic-body"]
    assert filtered[0]["input_tokens"] == 9_000_000_000_000_000_000
    assert log_db.management_logs_count() == 4
    assert log_db.management_logs_count(query="BODY-NEEDLE") == 1

    options = log_db.management_log_filter_options()
    assert {item["value"]: item["count"] for item in options["statuses"]} == {
        "success": 3, "error": 1,
    }
    assert {item["value"]: item["count"] for item in options["apiKeys"]} == {
        "shared-key": 3, "body-key": 1,
    }
    assert "ignored-unrelated" not in json.dumps(options)
    assert "ignored-invalid-month" not in json.dumps(options)

    detail = log_db.management_log_detail("historic-body")
    assert detail["log"]["request_id"] == "historic-body"
    assert json.loads(detail["detail"]["request_body"])["api_key"] == "business-api-key"
    assert log_db.management_log_detail("does-not-exist")["log"] is None


class _BoundedCursor:
    def __init__(self, cursor, fetch_sizes):
        self._cursor = cursor
        self._fetch_sizes = fetch_sizes

    def fetchmany(self, size):
        rows = self._cursor.fetchmany(size)
        self._fetch_sizes.append(len(rows))
        return rows

    def fetchall(self):
        raise AssertionError("globally paged data cursor must not use fetchall")

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _BoundedConnection:
    def __init__(self, conn, fetch_sizes, page_sql):
        self._conn = conn
        self._fetch_sizes = fetch_sizes
        self._page_sql = page_sql

    def execute(self, sql, parameters=()):
        cursor = self._conn.execute(sql, parameters)
        normalized = sql.lstrip().upper()
        if (
            normalized.startswith("SELECT")
            and "FROM REQUEST_LOG" in normalized
            and "ORDER BY" in normalized
        ):
            self._page_sql.append(sql)
            return _BoundedCursor(cursor, self._fetch_sizes)
        return cursor

    def create_collation(self, *args):
        return self._conn.create_collation(*args)

    def close(self):
        return self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_cross_month_random_page_streams_bounded_prefixes(
    monthly_log_store, monkeypatch,
):
    rows_per_month = 300
    for month_key, base_latency in (("newer", 0), ("older", 1_000)):
        start = monthly_log_store[month_key]
        _create_month(monthly_log_store, start, [
            {
                "id": f"{month_key}-{index:04d}",
                "created_at": (start + timedelta(days=10, seconds=index)).timestamp(),
                "latency": base_latency + index,
            }
            for index in range(rows_per_month)
        ])

    fetch_sizes: list[int] = []
    page_sql: list[str] = []
    live = log_db._get_conn()
    original_open = log_db._open_readonly
    monkeypatch.setattr(log_db, "_MANAGEMENT_TEXT_BATCH_SIZE", 7)
    monkeypatch.setattr(
        log_db, "_get_conn",
        lambda: _BoundedConnection(live, fetch_sizes, page_sql),
    )
    monkeypatch.setattr(
        log_db, "_open_readonly",
        lambda path: _BoundedConnection(
            original_open(path), fetch_sizes, page_sql,
        ),
    )

    rows, total = log_db.management_logs_page(
        sort="latency", descending=True, page=2, page_size=5,
    )

    assert total == rows_per_month * 2
    assert len(rows) == 5
    assert fetch_sizes and max(fetch_sizes) <= 7
    assert all("LIMIT ?" in sql and "OFFSET" not in sql for sql in page_sql)


def test_real_logs_control_and_asgi_reach_history_preserve_business_body_and_permissions(
    monthly_log_store, tmp_path,
):
    payloads = _install_historical_rows(monthly_log_store)
    controls = fake_controls()
    controls.logs = LogsControl(log_db=log_db)
    management_dir = tmp_path / "management"
    management_dir.mkdir()
    client, runtime, _installed, auth = build_client(
        management_dir, controls_value=controls,
    )

    listing = client.get(
        "/api/management/v1/logs",
        params={"sort": "latency", "descending": "true", "pageSize": 2},
        headers=auth,
    )
    assert listing.status_code == 200, listing.text
    assert listing.json()["meta"]["total"] == 4
    assert [row["id"] for row in listing.json()["data"]] == [
        "old-high", "historic-body",
    ]

    filtered = client.get(
        "/api/management/v1/logs",
        params={
            "apiKey": "body-key", "model": "body-model", "channel": "api:body",
            "protocol": "chat", "query": "body-needle",
        },
        headers=auth,
    )
    assert filtered.status_code == 200, filtered.text
    assert [row["id"] for row in filtered.json()["data"]] == ["historic-body"]
    assert filtered.json()["data"][0]["inputTokens"] == 9_000_000_000_000_000_000

    options = client.get("/api/management/v1/logs/filter-options", headers=auth)
    assert options.status_code == 200, options.text
    assert {item["value"]: item["count"] for item in options.json()["data"]["statuses"]} == {
        "success": 3, "error": 1,
    }

    detail = client.get("/api/management/v1/logs/historic-body", headers=auth)
    assert detail.status_code == 200, detail.text
    assert detail.json()["data"]["requestBodyAvailable"] is True
    assert detail.json()["data"]["requestHeadersAvailable"] is True
    assert "header-secret" not in detail.text

    raw_request = client.get(
        "/api/management/v1/logs/historic-body/raw-body",
        params={"kind": "request"}, headers=auth,
    )
    assert raw_request.status_code == 200, raw_request.text
    assert raw_request.json()["data"]["body"] == payloads["request"]
    raw_response = client.get(
        "/api/management/v1/logs/historic-body/raw-body",
        params={"kind": "response"}, headers=auth,
    )
    assert raw_response.status_code == 200, raw_response.text
    assert raw_response.json()["data"]["body"] == payloads["response"]

    body = client.get(
        "/api/management/v1/logs/historic-body/body",
        params={"kind": "request", "itemKind": "params"}, headers=auth,
    )
    assert body.status_code == 200, body.text
    params_item = body.json()["data"][0]
    parsed_params = json.loads(params_item["raw"])
    assert parsed_params["token"] == "business-token"
    assert parsed_params["api_key"] == "business-api-key"
    assert parsed_params["password"] == "business-password"
    assert "encrypted_content 已省略" in parsed_params["encrypted_content"]
    assert parsed_params["encrypted_content"] != payloads["encrypted"]

    full_item = client.get(
        "/api/management/v1/logs/historic-body/body/items/item_1",
        params={"kind": "request"}, headers=auth,
    )
    assert full_item.status_code == 200, full_item.text
    assert json.loads(full_item.json()["data"]["raw"])["token"] == "business-token"

    assert client.get(
        "/api/management/v1/logs/does-not-exist", headers=auth,
    ).status_code == 404
    assert client.get(
        "/api/management/v1/logs/does-not-exist/raw-body",
        params={"kind": "request"}, headers=auth,
    ).status_code == 404

    read_only = runtime.sessions.issue_for_principal(
        subject_id="read-only-real-session", auth_method=AuthMethod.MANAGEMENT_KEY,
        roles=(), capabilities=(Capability.READ,),
    )
    read_headers = {"Authorization": f"Bearer {read_only.credential}"}
    assert client.get(
        "/api/management/v1/logs/historic-body", headers=read_headers,
    ).status_code == 200
    denied = client.get(
        "/api/management/v1/logs/historic-body/raw-body",
        params={"kind": "request"}, headers=read_headers,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "CAPABILITY_DENIED"
    assert client.get(
        "/api/management/v1/logs/historic-body/raw-body",
        params={"kind": "request"},
    ).status_code == 401

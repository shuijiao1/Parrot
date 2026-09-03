from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from src.management_api.dependencies import get_management_context
from src.management_auth import AuthMethod, Capability, ManagementPrincipal
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode
from src.management_control.observability import (
    BodySort, LogBodyKind, LogsControl, RequestLogQuery, RequestLogSort,
    RequestLogStatus, RequestProtocol,
)
from src.management_control.observability.common import sanitize_credentials
from src.tests.management_observability_support import build_client


def context():
    return ManagementContext(
        request_id="logs-request",
        actor=ManagementPrincipal.administrator(
            subject_id="logs-actor", auth_method=AuthMethod.MANAGEMENT_KEY,
        ),
    )


class FakeLogDb:
    def __init__(self):
        self.rows = [
            {
                "request_id": "r3", "status": "error", "created_at": 300,
                "api_key_name": "key-b", "requested_model": "m2",
                "final_channel_key": "api:b", "ingress_protocol": "chat",
                "duration_ms": 300, "error_message": "needle failure",
            },
            {
                "request_id": "r2", "status": "success", "created_at": 200,
                "api_key_name": "key-a", "requested_model": "m1",
                "final_channel_key": "api:a", "ingress_protocol": "anthropic",
                "duration_ms": 100,
            },
            {
                "request_id": "r1", "status": "pending", "created_at": 100,
                "api_key_name": "key-a", "requested_model": "m1",
                "final_channel_key": "api:a", "ingress_protocol": "responses",
                "duration_ms": 0,
            },
        ]

    def _filtered(self, **kwargs):
        rows = self.rows
        if kwargs.get("status"):
            rows = [row for row in rows if row["status"] == kwargs["status"]]
        if kwargs.get("api_keys"):
            rows = [row for row in rows if row["api_key_name"] in kwargs["api_keys"]]
        if kwargs.get("models"):
            rows = [row for row in rows if row["requested_model"] in kwargs["models"]]
        if kwargs.get("channel_keys"):
            rows = [row for row in rows if row["final_channel_key"] in kwargs["channel_keys"]]
        return rows

    def recent_logs_count(self, **kwargs):
        return len(self._filtered(**kwargs))

    def recent_logs(self, limit, offset=0, **kwargs):
        return self._filtered(**kwargs)[offset:offset + limit]

    def recent_log_values(self, kind):
        field = {"apikey": "api_key_name", "model": "requested_model", "channel": "final_channel_key"}[kind]
        return sorted({row[field] for row in self.rows})

    def cost_for_log(self, row):
        return {"cost_ticks": 0}

    def log_detail(self, request_id):
        row = next((row for row in self.rows if row["request_id"] == request_id), None)
        if row is None:
            return {"log": None, "detail": None, "retry_chain": [], "proxy_chain": [], "local_web_log": [], "billing_attempts": []}
        return {
            "log": row,
            "detail": {
                "request_headers": json.dumps({"Authorization": "Bearer secret"}),
                "request_body": json.dumps({"model": "m", "api_key": "secret", "messages": [{"role": "user", "content": "hello"}]}),
                "response_body": json.dumps({"choices": [{"message": {"role": "assistant", "content": "ok"}}]}),
            },
            "retry_chain": [{"outcome": "success", "authorization": "secret"}],
            "proxy_chain": [], "local_web_log": [], "billing_attempts": [],
        }


class FakeConfig:
    def get(self):
        return {"apiKeys": {"key-a": "write-only"}, "channels": [{"name": "a"}], "logStoreBodies": True}


class FakeOAuth:
    def list_accounts(self):
        return []

    def _account_key(self, account):
        return ""


def test_logs_api_all_operations_control_once_schema_validation_and_missing(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    cases = [
        ("/api/management/v1/logs?status=success&pageSize=10", controls.logs.list_logs),
        ("/api/management/v1/logs/filter-options", controls.logs.filter_options),
        ("/api/management/v1/logs/req-1", controls.logs.detail),
        ("/api/management/v1/logs/req-1/body?kind=request", controls.logs.body_items),
        ("/api/management/v1/logs/req-1/body/items/item_1?kind=request", controls.logs.body_item),
        ("/api/management/v1/logs/req-1/raw-body?kind=request", controls.logs.raw_body),
    ]
    for path, mocked in cases:
        response = client.get(path, headers=auth)
        assert response.status_code == 200, response.text
        mocked.assert_called_once()
        actor = mocked.call_args.args[0].actor
        assert actor.subject_id == "administrator"
        if mocked is controls.logs.body_items:
            assert response.json()["meta"]["kindCounts"] == [
                {"kind": "user", "count": 1},
            ]

    bad = client.get("/api/management/v1/logs?status=unknown", headers=auth)
    assert bad.status_code == 422
    assert bad.json()["error"]["fields"][0]["path"] == "status[0]"
    unknown = client.get("/api/management/v1/logs?field=raw", headers=auth)
    assert unknown.status_code == 422
    assert unknown.json()["error"]["fields"][0]["path"] == "field"

    controls.logs.detail.side_effect = ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
    missing = client.get("/api/management/v1/logs/missing", headers=auth)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_body_endpoints_require_log_body_read_not_only_read(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    principal = ManagementPrincipal.with_capabilities(
        subject_id="read-only", auth_method=AuthMethod.MANAGEMENT_KEY,
        capabilities=(Capability.READ,), issued_at=datetime.now(timezone.utc),
        session_id="read-only-session",
    )
    client.app.dependency_overrides[get_management_context] = lambda: ManagementContext(
        request_id="body-denied", actor=principal,
    )
    paths = (
        "/api/management/v1/logs/req-1/body?kind=request",
        "/api/management/v1/logs/req-1/body/items/item_1?kind=request",
        "/api/management/v1/logs/req-1/raw-body?kind=request",
    )
    try:
        for path in paths:
            response = client.get(path, headers=auth)
            assert response.status_code == 403
            assert response.json()["error"]["code"] == "CAPABILITY_DENIED"
    finally:
        client.app.dependency_overrides.clear()
    controls.logs.body_items.assert_not_called()
    controls.logs.body_item.assert_not_called()
    controls.logs.raw_body.assert_not_called()


def test_sanitize_credentials_redacts_nested_keys_header_lines_and_url_userinfo():
    clean = sanitize_credentials({
        "Proxy-Authorization": "Basic nested-secret",
        "headerLine": (
            "Authorization: Bearer auth-secret, x-api-key=key-secret; "
            "password = password-secret"
        ),
        "dsn": "https://alice:url-secret@example.test/v1",
        "content": "ordinary business text remains unchanged",
    })

    assert clean["Proxy-Authorization"] == "<redacted>"
    assert clean["headerLine"] == (
        "Authorization: <redacted>, x-api-key=<redacted>; password = <redacted>"
    )
    assert clean["dsn"] == "https://alice:<redacted>@example.test/v1"
    assert clean["content"] == "ordinary business text remains unchanged"
    assert "secret" not in json.dumps(clean)


def test_logs_control_filter_sort_page_total_detail_and_secret_safe_body():
    control = LogsControl(log_db=FakeLogDb(), config=FakeConfig(), oauth_manager=FakeOAuth())
    ctx = context()
    result = control.list_logs(ctx, RequestLogQuery(
        statuses=(RequestLogStatus.ERROR, RequestLogStatus.SUCCESS),
        protocols=(RequestProtocol.CHAT,), query="needle",
        sort=RequestLogSort.LATENCY, page=1, page_size=1,
    ))
    assert result.total == 1
    assert result.items[0]["id"] == "r3"

    detail = control.detail(ctx, "r3")
    assert detail["requestBodyAvailable"] is True
    assert "secret" not in json.dumps(detail, default=str)
    body = control.body_items(
        ctx, "r3", kind=LogBodyKind.REQUEST, query=None,
        sort=BodySort.ORIGINAL, item_kind=None, page=1, page_size=50,
    )
    assert body.total >= 1
    assert sum(item["count"] for item in body.kind_counts) >= body.total
    raw = control.raw_body(ctx, "r3", kind=LogBodyKind.REQUEST)
    assert raw["body"]["api_key"] == "<redacted>"
    assert "secret" not in json.dumps(raw)
    item = control.body_item(ctx, "r3", kind=LogBodyKind.REQUEST, item_id="item_1")
    assert item["id"] == "item_1"

    with pytest.raises(ManagementError) as missing:
        control.detail(ctx, "missing")
    assert missing.value.code is ManagementErrorCode.RESOURCE_NOT_FOUND


def test_body_kind_counts_follow_search_before_kind_filter_and_page():
    control = LogsControl(log_db=FakeLogDb(), config=FakeConfig(), oauth_manager=FakeOAuth())
    db = control.log_db
    db.rows[0]["request_id"] = "body-counts"
    db.log_detail = lambda _request_id: {
        "log": db.rows[0],
        "detail": {"request_body": json.dumps({
            "messages": [
                {"role": "user", "content": "same needle"},
                {"role": "assistant", "content": "same needle"},
            ],
        })},
    }

    result = control.body_items(
        context(), "body-counts", kind=LogBodyKind.REQUEST, query="needle",
        sort=BodySort.ORIGINAL, item_kind="user", page=2, page_size=1,
    )

    assert result.total == 1
    assert result.items == ()
    assert result.kind_counts == (
        {"kind": "assistant", "count": 1},
        {"kind": "user", "count": 1},
    )


def test_logs_nondefault_and_filter_options_scan_in_bounded_chunks_with_exact_total():
    class LargeLogDb(FakeLogDb):
        def __init__(self):
            self.rows = [
                {
                    "request_id": f"r{i:04d}",
                    "status": "success" if i % 3 else "error",
                    "created_at": i,
                    "api_key_name": f"key-{i % 5}",
                    "requested_model": f"model-{i % 7}",
                    "final_channel_key": f"api:{i % 4}",
                    "ingress_protocol": "chat" if i % 2 else "anthropic",
                    "duration_ms": (i * 37) % 1000,
                }
                for i in range(999, -1, -1)
            ]
            self.limits = []

        def recent_logs(self, limit, offset=0, **kwargs):
            self.limits.append(limit)
            return super().recent_logs(limit, offset=offset, **kwargs)

    db = LargeLogDb()
    control = LogsControl(log_db=db, config=FakeConfig(), oauth_manager=FakeOAuth())
    query = RequestLogQuery(
        protocols=(RequestProtocol.CHAT,), sort=RequestLogSort.LATENCY,
        descending=True, page=2, page_size=17,
    )
    result = control.list_logs(context(), query)
    expected = [row for row in db.rows if row["ingress_protocol"] == "chat"]
    expected.sort(key=lambda row: row["duration_ms"], reverse=True)
    assert result.total == len(expected) == 500
    assert [item["id"] for item in result.items] == [
        row["request_id"] for row in expected[17:34]
    ]
    assert len(db.limits) == 5
    assert max(db.limits) <= 200

    db.limits.clear()
    options = control.filter_options(context())
    assert max(db.limits) <= 200
    assert len(db.limits) == 5
    assert sum(item["count"] for item in options["statuses"]) == 1000
    assert {item["value"] for item in options["apiKeys"]} == {
        f"key-{index}" for index in range(5)
    }

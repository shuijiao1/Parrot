from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.management_api.dependencies import get_management_context
from src.management_auth import AuthMethod, Capability, ManagementPrincipal
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode
from src.management_control.observability import (
    BodySort, LogBodyKind, LogsControl, RequestLogQuery, RequestLogSort,
    RequestLogStatus, RequestProtocol,
)
from src.management_control.observability import inspector
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
        self.cost_calls = []
        self.cost_batch_calls = []
        self.page_calls = []
        self.filter_options_calls = 0
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

    def management_logs_page(self, **kwargs):
        self.page_calls.append(kwargs)
        rows = list(self.rows)
        if kwargs.get("statuses"):
            rows = [row for row in rows if row["status"] in kwargs["statuses"]]
        if kwargs.get("api_keys"):
            rows = [row for row in rows if row["api_key_name"] in kwargs["api_keys"]]
        if kwargs.get("models"):
            rows = [row for row in rows if (
                row.get("requested_model") in kwargs["models"]
                or row.get("final_model") in kwargs["models"]
            )]
        if kwargs.get("channel_keys"):
            rows = [row for row in rows if row["final_channel_key"] in kwargs["channel_keys"]]
        if kwargs.get("protocols"):
            rows = [row for row in rows if (
                row.get("protocol") or row.get("ingress_protocol") or ""
            ) in kwargs["protocols"]]
        if kwargs.get("started_at") is not None:
            rows = [row for row in rows if row["created_at"] >= kwargs["started_at"]]
        if kwargs.get("ended_at") is not None:
            rows = [row for row in rows if row["created_at"] <= kwargs["ended_at"]]
        if kwargs.get("query"):
            needle = kwargs["query"].casefold()
            fields = (
                "request_id", "requested_model", "final_model",
                "final_channel_key", "api_key_name", "error_message",
            )
            rows = [row for row in rows if any(
                needle in str(row.get(field) or "").casefold() for field in fields
            )]
        sort = kwargs.get("sort")
        if sort == "status":
            key = lambda row: str(row.get("status") or "")
        elif sort == "latency":
            key = lambda row: float(row.get("duration_ms") or row.get("total_time_ms") or 0)
        elif sort == "model":
            key = lambda row: str(row.get("requested_model") or row.get("final_model") or "").casefold()
        else:
            key = lambda row: row["created_at"]
        rows.sort(key=key, reverse=bool(kwargs.get("descending")))
        total = len(rows)
        start = (kwargs["page"] - 1) * kwargs["page_size"]
        return rows[start:start + kwargs["page_size"]], total

    def management_log_filter_options(self):
        self.filter_options_calls += 1
        counts = {
            "apiKeys": {}, "channels": {}, "statuses": {}, "protocols": {}, "models": {},
        }
        fields = {
            "apiKeys": "api_key_name", "channels": "final_channel_key",
            "statuses": "status", "protocols": "ingress_protocol",
        }
        for row in self.rows:
            for public, field in fields.items():
                value = row.get(field)
                if value:
                    counts[public][str(value)] = counts[public].get(str(value), 0) + 1
            for value in {str(row.get("requested_model") or ""), str(row.get("final_model") or "")} - {""}:
                counts["models"][value] = counts["models"].get(value, 0) + 1
        return {
            public: [
                {"value": value, "count": count}
                for value, count in sorted(values.items(), key=lambda item: (-item[1], item[0]))
            ]
            for public, values in counts.items()
        }

    def cost_for_log(self, row):
        self.cost_calls.append(row["request_id"])
        ticks = {"r3": 300, "r2": 200, "r1": 100}.get(row["request_id"], 0)
        return {
            "cost_ticks": ticks,
            "actual_cost_ticks": ticks,
            "estimated_cost_ticks": 0,
            "actual_costed_success": int(ticks > 0),
            "estimated_costed_success": 0,
            "costed_success": int(ticks > 0),
            "unpriced_success": 0,
        }

    def costs_for_logs(self, rows):
        self.cost_batch_calls.append([row["request_id"] for row in rows])
        return {row["request_id"]: self.cost_for_log(row) for row in rows}

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
    assert result.items[0]["channelId"] == "api:b"

    detail = control.detail(ctx, "r3")
    assert detail["requestBodyAvailable"] is True
    assert detail["log"]["channelId"] == "api:b"
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


def test_logs_list_revision_tracks_public_channel_and_error_text():
    first_secret = "P4_REVISION_SECRET_ONE"
    second_secret = "P4_REVISION_SECRET_TWO"
    db = FakeLogDb()
    row = db.rows[0]
    row["final_channel_key"] = "api:one"
    row["error_message"] = f"upstreamSecret={first_secret}; retry failed"
    control = LogsControl(log_db=db, config=FakeConfig(), oauth_manager=FakeOAuth())

    original = control.list_logs(context(), RequestLogQuery(page_size=1)).items[0]
    row["final_channel_key"] = "api:two"
    channel_changed = control.list_logs(context(), RequestLogQuery(page_size=1)).items[0]

    assert original["channelId"] == "api:one"
    assert channel_changed["channelId"] == "api:two"
    assert original["revision"] != channel_changed["revision"]

    row["error_message"] = f"upstreamSecret={second_secret}; retry failed"
    secret_changed = control.list_logs(context(), RequestLogQuery(page_size=1)).items[0]

    assert original["error"] == f"upstreamSecret={first_secret}; retry failed"
    assert secret_changed["error"] == f"upstreamSecret={second_secret}; retry failed"
    assert channel_changed["revision"] != secret_changed["revision"]


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


def test_logs_nondefault_and_filter_options_delegate_one_sql_shaped_query_with_exact_total():
    class LargeLogDb(FakeLogDb):
        def __init__(self):
            self.cost_calls = []
            self.cost_batch_calls = []
            self.page_calls = []
            self.filter_options_calls = 0
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
    assert db.limits == []
    assert len(db.page_calls) == 1

    options = control.filter_options(context())
    assert db.limits == []
    assert db.filter_options_calls == 1
    assert sum(item["count"] for item in options["statuses"]) == 1000
    assert {item["value"] for item in options["apiKeys"]} == {
        f"key-{index}" for index in range(5)
    }


def test_response_parser_accepts_dict_without_changing_json_string_results():
    payload = {
        "choices": [{
            "message": {"role": "assistant", "content": "structured answer"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3},
    }

    from_dict = inspector.parse_response_body(payload)
    from_string = inspector.parse_response_body(json.dumps(payload))

    assert from_dict == from_string
    assert [item["kind"] for item in from_dict] == ["assistant", "finish", "usage"]
    assert from_dict[0]["text"] == "structured answer"


def test_logs_control_and_http_structure_sanitized_json_response_body(tmp_path):
    marker = "P4_SECRET_MARKER"
    db = FakeLogDb()
    original_detail = db.log_detail

    def detail(request_id):
        value = original_detail(request_id)
        value["detail"]["response_body"] = json.dumps({
            "choices": [{
                "message": {"role": "assistant", "content": "ordinary response"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3},
            "github_token": marker,
            "upstreamSecret": marker,
        })
        return value

    db.log_detail = detail
    control = LogsControl(log_db=db, config=FakeConfig(), oauth_manager=FakeOAuth())
    result = control.body_items(
        context(), "r3", kind=LogBodyKind.RESPONSE, query=None,
        sort=BodySort.ORIGINAL, item_kind=None, page=1, page_size=50,
    )
    assert [item["kind"] for item in result.items] == ["assistant", "finish", "usage"]
    assert result.kind_counts == (
        {"kind": "assistant", "count": 1},
        {"kind": "finish", "count": 1},
        {"kind": "usage", "count": 1},
    )
    assert marker not in json.dumps(result.items)

    client, _, controls, auth = build_client(tmp_path)
    controls.logs = control
    response = client.get(
        "/api/management/v1/logs/r3/body?kind=response", headers=auth,
    )
    assert response.status_code == 200, response.text
    assert [item["kind"] for item in response.json()["data"]] == [
        "assistant", "finish", "usage",
    ]
    assert marker not in response.text


def test_logs_list_uses_authoritative_transport_and_page_billing_only(tmp_path):
    db = FakeLogDb()
    db.rows[0]["upstream_transport"] = "websocket"
    db.rows[0]["transport"] = "not-authoritative"
    db.rows[0]["error_message"] = (
        "upstreamSecret=P4_SECRET_MARKER; ordinary upstream failure"
    )
    control = LogsControl(log_db=db, config=FakeConfig(), oauth_manager=FakeOAuth())

    result = control.list_logs(context(), RequestLogQuery(page=1, page_size=2))

    assert [item["id"] for item in result.items] == ["r3", "r2"]
    assert db.cost_calls == ["r3", "r2"]
    assert db.cost_batch_calls == [["r3", "r2"]]
    assert len(db.cost_calls) <= result.page_size
    assert result.items[0]["transport"] == "websocket"
    assert result.items[0]["costTicks"] == 300
    assert result.items[0]["error"] == (
        "upstreamSecret=P4_SECRET_MARKER; ordinary upstream failure"
    )
    assert result.items[0]["billing"] == {
        "costTicks": 300,
        "actualCostTicks": 300,
        "estimatedCostTicks": 0,
        "actualCostedSuccess": 1,
        "estimatedCostedSuccess": 0,
        "costedSuccess": 1,
        "unpricedSuccess": 0,
    }

    db.cost_calls.clear()
    db.cost_batch_calls.clear()
    client, _, controls, auth = build_client(tmp_path)
    controls.logs = control
    response = client.get(
        "/api/management/v1/logs?pageSize=2", headers=auth,
    )
    assert response.status_code == 200, response.text
    assert db.cost_calls == ["r3", "r2"]
    assert db.cost_batch_calls == [["r3", "r2"]]
    assert response.json()["data"][0]["error"] == (
        "upstreamSecret=P4_SECRET_MARKER; ordinary upstream failure"
    )
    assert response.json()["data"][0]["billing"]["actualCostTicks"] == 300
    assert response.json()["data"][0]["channelId"] == "api:b"


def test_logs_cost_sort_is_rejected_and_model_options_match_or_filter_semantics(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    rejected = client.get("/api/management/v1/logs?sort=cost", headers=auth)
    assert rejected.status_code == 422
    controls.logs.list_logs.assert_not_called()

    db = FakeLogDb()
    db.rows[0]["final_model"] = "m-final"
    db.rows[1]["final_model"] = "m1"
    db.rows[2]["final_model"] = "m2"
    options = LogsControl(
        log_db=db, config=FakeConfig(), oauth_manager=FakeOAuth(),
    ).filter_options(context())
    assert {item["value"]: item["count"] for item in options["models"]} == {
        "m1": 2,
        "m2": 2,
        "m-final": 1,
    }


@pytest.mark.parametrize("prefix", ["/api/management/v1/logs", "/api/management/v1/media-logs"])
def test_log_and_media_http_time_bounds_require_rfc3339_timezone_and_order(prefix, tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    target = controls.logs.list_logs if prefix.endswith("/logs") else controls.media.list_logs
    for params in (
        {"startedAt": "2026-01-02T03:04:05"},
        {"startedAt": "2026-01-02 03:04:05Z"},
        {
            "startedAt": "2026-01-03T03:04:05Z",
            "endedAt": "2026-01-02T03:04:05Z",
        },
    ):
        response = client.get(prefix, params=params, headers=auth)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
    target.assert_not_called()

    valid = client.get(
        prefix,
        params={
            "startedAt": "2026-01-02T11:04:05+08:00",
            "endedAt": "2026-01-02T04:04:05Z",
        },
        headers=auth,
    )
    assert valid.status_code == 200, valid.text
    query = target.call_args.args[1]
    assert query.started_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert query.ended_at == datetime(2026, 1, 2, 4, 4, 5, tzinfo=timezone.utc)


def test_log_control_time_bounds_reject_naive_and_reverse_without_type_error():
    control = LogsControl(log_db=FakeLogDb(), config=FakeConfig(), oauth_manager=FakeOAuth())
    for query, path in (
        (RequestLogQuery(started_at=datetime(2026, 1, 2, 3, 4, 5)), "startedAt"),
        (RequestLogQuery(
            started_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            ended_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        ), "endedAt"),
        (RequestLogQuery(
            started_at=datetime(2026, 1, 2, 11, tzinfo=timezone(timedelta(hours=8))),
            ended_at=datetime(2026, 1, 2, 4, tzinfo=timezone.utc),
        ), None),
    ):
        if path is None:
            control.list_logs(context(), query)
            continue
        with pytest.raises(ManagementError) as invalid:
            control.list_logs(context(), query)
        assert invalid.value.code is ManagementErrorCode.VALIDATION_FAILED
        assert invalid.value.fields[0].path == path

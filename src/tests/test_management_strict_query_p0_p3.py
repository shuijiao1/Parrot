from __future__ import annotations

import ast
import copy
import inspect
import sys
import textwrap
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.management_api.routers import apikey as apikey_router
from src.management_api.routers import foundation as foundation_router
from src.tests.test_management_api_foundation import (
    FAKE_KEY,
    bearer,
    build_app as build_foundation_app,
    create_session,
)
from src.tests.test_management_apikey_api import (
    build_app as build_apikey_app,
    session_headers,
)


P0_ALLOW_LISTS = {
    "createManagementSession": frozenset(),
    "getCurrentManagementSession": frozenset(),
    "revokeCurrentManagementSession": frozenset(),
    "createTelegramApproval": frozenset(),
    "getTelegramApproval": frozenset(),
    "getManagementMetadata": frozenset(),
    "getManagementCapabilities": frozenset(),
    "getManagementOperation": frozenset(),
    "cancelManagementOperation": frozenset(),
}
P3_ALLOW_LISTS = {
    "listApiKeys": frozenset({"page", "pageSize", "enabled", "source", "name", "sort"}),
    "createApiKey": frozenset(),
    "getApiKey": frozenset(),
    "updateApiKey": frozenset(),
    "deleteApiKey": frozenset(),
    "planApiKeyRegeneration": frozenset(),
    "regenerateApiKey": frozenset(),
    "replaceApiKeySecret": frozenset(),
    "reorderApiKeys": frozenset(),
    "resetApiKeyLimiter": frozenset(),
    "getApiKeyStats": frozenset(),
}
EXPECTED_ALLOW_LISTS = {**P0_ALLOW_LISTS, **P3_ALLOW_LISTS}


@dataclass(frozen=True)
class RequestCase:
    operation_id: str
    method: str
    path: str
    body: dict[str, Any] | None = None
    extra_headers: dict[str, str] | None = None
    mutation: bool = False


P0_REQUESTS = (
    RequestCase(
        "createManagementSession",
        "post",
        "/api/management/v1/auth/sessions",
        {"grantType": "managementKey", "managementKey": FAKE_KEY},
        mutation=True,
    ),
    RequestCase("getCurrentManagementSession", "get", "/api/management/v1/auth/session"),
    RequestCase("revokeCurrentManagementSession", "delete", "/api/management/v1/auth/session", mutation=True),
    RequestCase(
        "createTelegramApproval",
        "post",
        "/api/management/v1/auth/telegram-approvals",
        {"clientName": "strict-query", "deviceSummary": "test-device"},
        mutation=True,
    ),
    RequestCase(
        "getTelegramApproval",
        "get",
        "/api/management/v1/auth/telegram-approvals/approval-test",
        extra_headers={"Authorization": "Approval exchange-test"},
    ),
    RequestCase("getManagementMetadata", "get", "/api/management/v1/meta"),
    RequestCase("getManagementCapabilities", "get", "/api/management/v1/capabilities"),
    RequestCase("getManagementOperation", "get", "/api/management/v1/operations/operation-test"),
    RequestCase(
        "cancelManagementOperation",
        "delete",
        "/api/management/v1/operations/operation-test",
        mutation=True,
    ),
)
P3_REQUESTS = (
    RequestCase("listApiKeys", "get", "/api/management/v1/api-keys"),
    RequestCase(
        "createApiKey",
        "post",
        "/api/management/v1/api-keys",
        {"mode": "generated", "name": "strict-query-new"},
        mutation=True,
    ),
    RequestCase("getApiKey", "get", "/api/management/v1/api-keys/alpha"),
    RequestCase(
        "updateApiKey",
        "patch",
        "/api/management/v1/api-keys/alpha",
        {"enabled": False},
        mutation=True,
    ),
    RequestCase(
        "deleteApiKey",
        "delete",
        "/api/management/v1/api-keys/alpha",
        extra_headers={"If-Match": '"ak-fake"'},
        mutation=True,
    ),
    RequestCase(
        "planApiKeyRegeneration",
        "post",
        "/api/management/v1/api-keys/alpha/actions/generate-replacement-plan",
        mutation=True,
    ),
    RequestCase(
        "regenerateApiKey",
        "post",
        "/api/management/v1/api-keys/alpha/actions/generate-replacement",
        {"planId": "akplan_fake", "planToken": "fake-plan-token"},
        mutation=True,
    ),
    RequestCase(
        "replaceApiKeySecret",
        "put",
        "/api/management/v1/api-keys/alpha/secret",
        {"customSecret": "replacement-secret"},
        {"If-Match": '"ak-fake"'},
        mutation=True,
    ),
    RequestCase(
        "reorderApiKeys",
        "put",
        "/api/management/v1/api-keys/order",
        {"keyIds": ["alpha", "busy"]},
        {"If-Match": '"aks-fake"'},
        mutation=True,
    ),
    RequestCase(
        "resetApiKeyLimiter",
        "post",
        "/api/management/v1/api-keys/alpha/actions/reset-limiter",
        mutation=True,
    ),
    RequestCase("getApiKeyStats", "get", "/api/management/v1/api-keys/alpha/stats"),
)


def _operation_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        operation["operationId"]: operation
        for path_item in document["paths"].values()
        for method, operation in path_item.items()
        if method in {"get", "post", "patch", "put", "delete"}
        and operation.get("operationId") in EXPECTED_ALLOW_LISTS
    }


def _guard_allowed_set(module, call: ast.Call) -> frozenset[str]:
    if len(call.args) == 1:
        return frozenset()
    assert len(call.args) == 2 and not call.keywords
    allowed = call.args[1]
    assert isinstance(allowed, ast.Name)
    return frozenset(getattr(module, allowed.id))


def _sqlite_state_snapshot(runtime) -> tuple[Any, ...]:
    store = runtime.state_store
    with store._lock:
        tables = []
        for table in ("sessions", "approvals", "audit"):
            rows = store._conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            tables.append((table, tuple(tuple(row) for row in rows)))
    with runtime.operations._lock:
        operations = copy.deepcopy(tuple(runtime.operations._items.items()))
    return (*tables, operations)


def _apikey_side_effect_snapshot(runtime, control, config_store, limiter) -> tuple[Any, ...]:
    return (
        copy.deepcopy(config_store.value),
        config_store.update_calls,
        tuple(limiter.forgot),
        copy.deepcopy(limiter.snapshots),
        copy.deepcopy(control._plans),
        control._audit.snapshot(),
        _sqlite_state_snapshot(runtime),
    )


def _assert_unknown_query(response, name: str = "rogue") -> None:
    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_FAILED"
    assert error["fields"] == [
        {
            "path": name,
            "code": "UNKNOWN_QUERY_PARAMETER",
            "message": f"query parameter '{name}' is not supported",
        }
    ]


def test_ast_and_openapi_matrix_proves_all_20_routes_have_exactly_one_matching_guard(tmp_path):
    app, runtime, _, _, _ = build_apikey_app(tmp_path)
    try:
        operations = _operation_map(app.openapi())
        assert set(operations) == set(EXPECTED_ALLOW_LISTS)
        assert len(operations) == 20

        routes = [
            route
            for module in (foundation_router, apikey_router)
            for route in module.router.routes
            if isinstance(route, APIRoute)
        ]
        assert len(routes) == 20
        assert {route.operation_id for route in routes} == set(EXPECTED_ALLOW_LISTS)

        guarded_allow_lists = {}
        for route in routes:
            source = ast.parse(textwrap.dedent(inspect.getsource(route.endpoint)))
            function = next(
                node
                for node in source.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            guard_calls = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "reject_unknown_query_parameters"
            ]
            assert len(guard_calls) == 1, route.operation_id
            first_statement = function.body[0]
            assert isinstance(first_statement, ast.Expr)
            assert first_statement.value is guard_calls[0], route.operation_id

            module = sys.modules[route.endpoint.__module__]
            guarded_allow_lists[route.operation_id] = _guard_allowed_set(module, guard_calls[0])

        openapi_allow_lists = {
            operation_id: frozenset(
                parameter["name"]
                for parameter in operation.get("parameters", [])
                if parameter["in"] == "query"
            )
            for operation_id, operation in operations.items()
        }
        assert guarded_allow_lists == EXPECTED_ALLOW_LISTS
        assert openapi_allow_lists == EXPECTED_ALLOW_LISTS
        assert all("422" in operation["responses"] for operation in operations.values())
    finally:
        runtime.close()


def test_foundation_all_9_routes_reject_unknown_query_before_actions_or_state_changes(
    tmp_path, monkeypatch,
):
    app, runtime, _ = build_foundation_app(tmp_path)
    with TestClient(app) as client:
        credential = create_session(client)
        protected_headers = bearer(credential)
        calls = []

        def forbidden(*args, _label, **kwargs):
            calls.append(_label)
            raise AssertionError(f"action called before strict query rejection: {_label}")

        action_methods = (
            (runtime.sessions, "create_from_management_key"),
            (runtime.sessions, "create_from_telegram_approval"),
            (runtime.sessions, "revoke_current"),
            (runtime.approvals, "create"),
            (runtime.approvals, "get"),
            (runtime.operations, "get"),
            (runtime.operations, "cancel"),
        )
        for owner, name in action_methods:
            monkeypatch.setattr(
                owner,
                name,
                lambda *args, _label=f"{type(owner).__name__}.{name}", **kwargs: forbidden(
                    *args, _label=_label, **kwargs
                ),
            )

        assert {case.operation_id for case in P0_REQUESTS if case.mutation} == {
            "createManagementSession",
            "revokeCurrentManagementSession",
            "createTelegramApproval",
            "cancelManagementOperation",
        }
        for case in P0_REQUESTS:
            headers = dict(protected_headers)
            headers.update(case.extra_headers or {})
            before_state = _sqlite_state_snapshot(runtime)
            before_calls = tuple(calls)
            response = client.request(
                case.method,
                case.path,
                params={"rogue": "1"},
                headers=headers,
                json=case.body,
            )
            _assert_unknown_query(response)
            assert tuple(calls) == before_calls, case.operation_id
            assert _sqlite_state_snapshot(runtime) == before_state, case.operation_id
            assert FAKE_KEY not in response.text


def test_apikey_all_11_routes_reject_unknown_query_and_all_8_mutations_are_side_effect_free(
    tmp_path, monkeypatch,
):
    app, runtime, control, config_store, limiter = build_apikey_app(tmp_path)
    headers = session_headers(runtime)
    calls = []
    control_methods = (
        "list_api_keys",
        "create_api_key",
        "get_api_key",
        "update_api_key",
        "delete_api_key",
        "plan_regeneration",
        "regenerate_api_key",
        "replace_api_key_secret",
        "reorder_api_keys",
        "reset_api_key_limiter",
        "get_api_key_stats",
    )

    def forbidden(*args, _label, **kwargs):
        calls.append(_label)
        raise AssertionError(f"control called before strict query rejection: {_label}")

    for name in control_methods:
        monkeypatch.setattr(
            control,
            name,
            lambda *args, _label=name, **kwargs: forbidden(*args, _label=_label, **kwargs),
        )

    client = TestClient(app)
    try:
        assert {case.operation_id for case in P3_REQUESTS if case.mutation} == {
            "createApiKey",
            "updateApiKey",
            "deleteApiKey",
            "planApiKeyRegeneration",
            "regenerateApiKey",
            "replaceApiKeySecret",
            "reorderApiKeys",
            "resetApiKeyLimiter",
        }
        for case in P3_REQUESTS:
            request_headers = {**headers, **(case.extra_headers or {})}
            before = _apikey_side_effect_snapshot(runtime, control, config_store, limiter)
            before_calls = tuple(calls)
            response = client.request(
                case.method,
                case.path,
                params={"rogue": "1"},
                headers=request_headers,
                json=case.body,
            )
            _assert_unknown_query(response)
            assert tuple(calls) == before_calls, case.operation_id
            assert _apikey_side_effect_snapshot(runtime, control, config_store, limiter) == before
            for secret in ("alpha-secret", "fake-plan-token", "replacement-secret"):
                assert secret not in response.text
    finally:
        runtime.close()


def test_list_legal_duplicates_keep_fastapi_semantics_and_case_is_exact(tmp_path):
    app, runtime, _, _, _ = build_apikey_app(tmp_path)
    headers = session_headers(runtime)
    client = TestClient(app)
    try:
        legal = client.get(
            "/api/management/v1/api-keys",
            params=[
                ("page", "2"),
                ("page", "1"),
                ("pageSize", "2"),
                ("pageSize", "1"),
                ("enabled", "all"),
                ("source", "custom"),
                ("name", "alp"),
                ("sort", "nameAsc"),
            ],
            headers=headers,
        )
        assert legal.status_code == 200, legal.text
        assert legal.json()["meta"]["page"] == 1
        assert legal.json()["meta"]["pageSize"] == 1
        assert [item["keyId"] for item in legal.json()["data"]["items"]] == ["alpha"]

        _assert_unknown_query(
            client.get("/api/management/v1/api-keys", params={"Page": "1"}, headers=headers),
            "Page",
        )

        invalid_enum = client.get(
            "/api/management/v1/api-keys", params={"sort": "unknown"}, headers=headers,
        )
        assert invalid_enum.status_code == 422
        enum_field = invalid_enum.json()["error"]["fields"][0]
        assert enum_field["path"] == "sort"
        assert enum_field["code"] != "UNKNOWN_QUERY_PARAMETER"

        invalid_range = client.get(
            "/api/management/v1/api-keys", params={"pageSize": "201"}, headers=headers,
        )
        assert invalid_range.status_code == 422
        range_field = invalid_range.json()["error"]["fields"][0]
        assert range_field["path"] == "pageSize"
        assert range_field["code"] != "UNKNOWN_QUERY_PARAMETER"
    finally:
        runtime.close()


def test_protected_route_authorization_still_precedes_handler_query_guard(tmp_path):
    foundation_app, foundation_runtime, _ = build_foundation_app(tmp_path / "foundation")
    apikey_app, apikey_runtime, _, _, _ = build_apikey_app(tmp_path / "apikey")
    try:
        foundation = TestClient(foundation_app).get(
            "/api/management/v1/meta", params={"rogue": "1"},
        )
        assert foundation.status_code == 401
        assert foundation.json()["error"]["code"] == "SESSION_REQUIRED"

        apikey = TestClient(apikey_app).patch(
            "/api/management/v1/api-keys/alpha",
            params={"rogue": "1"},
            json={"enabled": False},
        )
        assert apikey.status_code == 401
        assert apikey.json()["error"]["code"] == "SESSION_REQUIRED"
    finally:
        foundation_runtime.close()
        apikey_runtime.close()

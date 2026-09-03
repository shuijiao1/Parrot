from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from src.management_api.dependencies import get_management_context
from src.management_auth import AuthMethod, Capability, ManagementPrincipal
from src.management_control import ManagementContext
from src.tests.management_system_network_support import bearer, build_p6_app, create_session


PREFIX = "/api/management/v1"
MANIFEST = Path("src/tests/fixtures/management_api/p6-operation-manifest.tsv")


def manifest():
    return [tuple(line.split("\t")) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line]


PATCHES = {
    "/settings/retry": {"transient": {"enabled": False, "maxExtraAttempts": 4, "backoffSeconds": [0, 1.25], "errors": {"xaiUnavailable": False}}, "recovery": {"oauthRefresh": False}},
    "/settings/timeouts": {"connect": 11},
    "/settings/error-cooldown": {"errorWindows": [2, 4, 0], "oauthGraceCount": 4, "ladderMinIntervalSeconds": 31, "permanentMinAgeSeconds": 301},
    "/settings/scoring": {"emaAlpha": 0.5, "recentWindow": 51, "errorPenaltyFactor": 9, "explorationRate": 0.1},
    "/settings/affinity": {"ttlMinutes": 31},
    "/settings/cch": {"mode": "dynamic"},
    "/settings/concurrency": {"enabled": False, "queueWaitSeconds": 0, "defaultMaxConcurrent": 7},
    "/settings/api-key-concurrency": {"enabled": False, "defaultMaxConcurrent": 6, "defaultMaxQueue": 51, "defaultQueueWaitSeconds": 61},
    "/settings/quota-monitor": {"enabled": True, "intervalSeconds": 120, "thresholdPercent": 91},
    "/settings/notifications": {"enabled": False, "events": {"networkMonitor": False}},
    "/settings/openai-websocket": {"responsesUpstreamWsForOAuth": True},
}


def request_values(method: str, path: str, operation_id: str):
    actual = path.replace("{channelId}", quote("api:example", safe="")).replace("{term}", quote("policy/violation", safe=""))
    body = None
    if method == "PATCH" and path in PATCHES:
        body = PATCHES[path]
    elif operation_id in {"addDefaultBlacklistTerm", "addChannelBlacklistTerm"}:
        body = {"term": "policy/violation"}
    elif operation_id in {"testDnsSettings"}:
        body = {"servers": ["1.1.1.1"]}
    elif operation_id in {"commitDnsSettings", "commitSocks5Settings"}:
        body = {"planId": "nplan_missing", "force": False}
    elif operation_id == "testSocks5Settings":
        body = {"url": "socks5://proxy.invalid:1080"}
    elif operation_id == "updateSocks5State":
        body = {"enabled": False}
    elif operation_id == "updateNetworkMonitor":
        body = {"dns": True}
    return actual, body


def test_p6_openapi_manifest_is_exact_unique_typed_and_secret_safe(tmp_path):
    app, _runtime, _fixture = build_p6_app(tmp_path)
    document = app.openapi()
    actual = []
    for path, item in document["paths"].items():
        if not path.startswith(PREFIX):
            continue
        for method, operation in item.items():
            if method.upper() not in {"GET", "PATCH", "POST", "DELETE"}:
                continue
            operation_id = operation["operationId"]
            if operation_id in {row[2] for row in manifest()}:
                actual.append((method.upper(), path.removeprefix(PREFIX), operation_id))
            assert operation.get("tags"), operation_id
    assert actual == manifest()
    assert len({row[2] for row in actual}) == 40
    schemas = document["components"]["schemas"]
    assert schemas["Socks5TestRequest"]["properties"]["url"]["writeOnly"] is True
    encoded = json.dumps(document, ensure_ascii=False).lower()
    for marker in ("test-marker", "alpha-marker", "password-marker"):
        assert marker not in encoded
    for _method, path, operation_id in actual:
        operation = document["paths"][PREFIX + path][_method.lower()]
        if operation_id not in {"clearDnsCache", "deleteDefaultBlacklistTerm", "deleteChannelBlacklistTerm"}:
            success = next(code for code in operation["responses"] if code.startswith("2"))
            assert "example" in operation["responses"][success]["content"]["application/json"]


def test_all_p6_routes_reject_unknown_query_before_auth_and_side_effects(tmp_path):
    app, runtime, fixture = build_p6_app(tmp_path)
    client = TestClient(app)
    for method, path, operation_id in manifest():
        actual, body = request_values(method, path, operation_id)
        config_before = copy.deepcopy(fixture.config.value)
        updates_before = fixture.config.updates
        events_before = copy.deepcopy(fixture.gateway.events)
        audit_before = fixture.audit.snapshot()
        operations_before = copy.deepcopy(runtime.operations._items)
        response = client.request(method, PREFIX + actual + "?undeclared=1", json=body)
        assert response.status_code == 422, (operation_id, response.text)
        assert response.json()["error"]["fields"] == [{
            "path": "undeclared", "code": "UNKNOWN_QUERY_PARAMETER",
            "message": "Unknown query parameter",
        }]
        assert fixture.config.value == config_before, operation_id
        assert fixture.config.updates == updates_before, operation_id
        assert fixture.gateway.events == events_before, operation_id
        assert fixture.audit.snapshot() == audit_before, operation_id
        assert runtime.operations._items == operations_before, operation_id


def test_all_p6_routes_require_a_session(tmp_path):
    app, _runtime, _fixture = build_p6_app(tmp_path)
    client = TestClient(app)
    for method, path, operation_id in manifest():
        actual, body = request_values(method, path, operation_id)
        response = client.request(method, PREFIX + actual, json=body)
        assert response.status_code == 401, (operation_id, response.text)
        assert response.json()["error"]["code"] == "SESSION_REQUIRED"


def test_every_p6_mutation_enforces_its_capability(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    read_only = ManagementContext(
        request_id="limited-request",
        actor=ManagementPrincipal.with_capabilities(
            subject_id="limited", auth_method=AuthMethod.MANAGEMENT_KEY,
            capabilities=(Capability.READ,), issued_at=datetime.now(timezone.utc),
            session_id="limited-session",
        ),
    )
    app.dependency_overrides[get_management_context] = lambda: read_only
    client = TestClient(app)
    for method, path, operation_id in manifest():
        if method == "GET":
            continue
        actual, body = request_values(method, path, operation_id)
        before = copy.deepcopy(fixture.config.value)
        response = client.request(method, PREFIX + actual, json=body)
        assert response.status_code == 403, (operation_id, response.text)
        assert response.json()["error"]["code"] == "CAPABILITY_DENIED"
        assert fixture.config.value == before


@pytest.mark.parametrize("path,patch", PATCHES.items())
def test_typed_settings_get_sparse_patch_revision_and_audit(tmp_path, path, patch):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before = client.get(PREFIX + path, headers=headers)
        assert before.status_code == 200, before.text
        old = before.json()["data"]
        response = client.patch(PREFIX + path, headers={**headers, "If-Match": old["revision"]}, json=patch)
        assert response.status_code == 200, response.text
        after = response.json()["data"]
        assert after["revision"] != old["revision"] or path == "/settings/openai-websocket"
        assert response.json()["meta"]["requestId"]
        assert fixture.audit.snapshot()[-1].result == "succeeded"
        if path == "/settings/timeouts":
            assert after["connect"] == 11
            assert after["firstByte"] == old["firstByte"]
        if path == "/settings/quota-monitor":
            quota = fixture.config.value["quotaMonitor"]
            assert quota["disableThresholdPercent"] == quota["resumeThresholdPercent"] == 91
        if path == "/settings/openai-websocket":
            assert "responsesUpstreamTransport" not in fixture.config.value["openai"]
            assert "responsesUpstreamWs" not in fixture.config.value["openai"]


def test_settings_strict_body_ranges_and_stale_revision_have_no_write(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        revision = client.get(PREFIX + "/settings/scoring", headers=headers).json()["data"]["revision"]
        for body in ({"unknown": 1}, {"emaAlpha": 2}, {"emaAlpha": None}):
            before = fixture.config.updates
            response = client.patch(PREFIX + "/settings/scoring", headers=headers, json=body)
            assert response.status_code == 422, response.text
            assert fixture.config.updates == before
        first = client.patch(PREFIX + "/settings/scoring", headers={**headers, "If-Match": revision}, json={"emaAlpha": 0.4})
        assert first.status_code == 200
        before = fixture.config.updates
        stale = client.patch(PREFIX + "/settings/scoring", headers={**headers, "If-Match": revision}, json={"emaAlpha": 0.3})
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "REVISION_CONFLICT"
        assert fixture.config.updates == before


def test_content_blacklist_order_duplicate_percent_path_cas_and_canonical_ids(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        initial = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        add = client.post(PREFIX + "/content-blacklist/default", headers={**headers, "If-Match": initial["revision"]}, json={"term": "policy/violation"})
        assert add.status_code == 201
        once = add.json()["data"]
        duplicate = client.post(PREFIX + "/content-blacklist/default", headers=headers, json={"term": "policy/violation"})
        assert duplicate.status_code == 201
        assert duplicate.json()["data"]["default"] == ["policy/violation"]
        assert duplicate.json()["data"]["revision"] == once["revision"]
        channel = client.post(PREFIX + "/content-blacklist/channels/api%3Aexample", headers=headers, json={"term": "second"})
        assert channel.status_code == 201, channel.text
        assert channel.json()["data"]["byChannel"] == [{"channelId": "api:example", "terms": ["second"]}]
        unknown = client.post(PREFIX + "/content-blacklist/channels/example", headers=headers, json={"term": "x"})
        assert unknown.status_code == 404
        deleted = client.delete(PREFIX + "/content-blacklist/default/" + quote("policy/violation", safe=""), headers=headers)
        assert deleted.status_code == 204
        channel_deleted = client.delete(PREFIX + "/content-blacklist/channels/api%3Aexample/second", headers=headers)
        assert channel_deleted.status_code == 204
        assert "api:example" not in fixture.config.value["contentBlacklist"]["byChannel"]
        current = client.post(PREFIX + "/content-blacklist/default", headers=headers, json={"term": "current"})
        assert current.status_code == 201
        stale = client.post(PREFIX + "/content-blacklist/default", headers={**headers, "If-Match": initial["revision"]}, json={"term": "later"})
        assert stale.status_code == 409

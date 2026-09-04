from __future__ import annotations

import base64
import copy
import json

from fastapi.testclient import TestClient

from src.tests.management_system_network_support import bearer, build_p6_app, create_session


PREFIX = "/api/management/v1"
SECRET_MARKERS = (
    "alpha-marker", "password-marker", "username-marker", "new-password-marker",
    "test-marker-bearer", "test-marker-refresh", "test-marker-dns",
    "generic-marker", "snake-marker", "session-marker", "camel-marker",
    "auth-marker", "cookie-marker", "escaped-marker", "username-only-marker",
    "tested-password-marker", "other-user-marker", "concurrent-password-marker",
)
PUBLIC_AUTH_PROSE = (
    "Bearer routing-mode", "Basic routing-mode", "bearer support-enabled",
    "Basic request-routing", "Bearer ordinary.word", "Basic routing mode",
    "Bearer support is enabled", "Bearer landmarker", "Bearer OrdinaryMode",
    'Bearer "routing-mode"',
)


def operation(client: TestClient, headers: dict[str, str], response):
    assert response.status_code == 202, response.text
    operation_id = response.json()["data"]["id"]
    polled = client.get(PREFIX + "/operations/" + operation_id, headers=headers)
    assert polled.status_code == 200, polled.text
    return polled.json()["data"]


def assert_secret_safe(value) -> None:
    encoded = json.dumps(value, ensure_ascii=False)
    for marker in SECRET_MARKERS:
        assert marker not in encoded


def test_dns_test_plan_commit_replay_and_audit(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before = client.get(PREFIX + "/network", headers=headers).json()["data"]
        tested = operation(client, headers, client.post(
            PREFIX + "/network/dns/tests", headers=headers, json={"servers": ["1.1.1.1", "1.1.1.1"]},
        ))
        assert tested["status"] == "succeeded"
        plan = tested["result"]["plan"]
        assert plan["passed"] is True
        assert plan["tested"] == {"servers": ["1.1.1.1"]}
        committed = client.post(
            PREFIX + "/network/dns/commits",
            headers={**headers, "If-Match": before["revision"]},
            json={"planId": plan["id"], "force": False},
        )
        assert committed.status_code == 200, committed.text
        assert committed.json()["data"]["dns"]["servers"] == ["1.1.1.1"]
        replay = client.post(
            PREFIX + "/network/dns/commits", headers=headers,
            json={"planId": plan["id"], "force": False},
        )
        assert replay.status_code == 409
        assert replay.json()["error"]["code"] == "STATE_CONFLICT"
        records = fixture.audit.snapshot()
        assert any(row.action == "network.dns.test" and row.result == "succeeded" for row in records)
        assert any(row.action == "network.dns.commit" and row.result == "succeeded" for row in records)
        assert any(row.action == "network.dns.commit" and row.result == "failed" for row in records)


def test_failed_dns_requires_force_and_force_cannot_apply_a_passed_plan(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    fixture.gateway.dns_passes = False
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        failed = operation(client, headers, client.post(
            PREFIX + "/network/dns/tests", headers=headers, json={"servers": ["9.9.9.9"]},
        ))
        assert failed["status"] == "succeeded"
        assert_secret_safe(failed)
        plan_id = failed["result"]["plan"]["id"]
        before = copy.deepcopy(fixture.config.value)
        blocked = client.post(PREFIX + "/network/dns/commits", headers=headers, json={"planId": plan_id, "force": False})
        assert blocked.status_code == 400
        assert blocked.json()["error"]["code"] == "CONFIRMATION_REQUIRED"
        assert fixture.config.value == before
        forced = client.post(PREFIX + "/network/dns/commits", headers=headers, json={"planId": plan_id, "force": True})
        assert forced.status_code == 200
        assert fixture.config.value["network"]["dns"]["servers"] == ["9.9.9.9"]

        fixture.gateway.dns_passes = True
        passed = operation(client, headers, client.post(PREFIX + "/network/dns/tests", headers=headers, json={"servers": ["8.8.4.4"]}))
        passed_id = passed["result"]["plan"]["id"]
        updates = fixture.config.updates
        needless_force = client.post(PREFIX + "/network/dns/commits", headers=headers, json={"planId": passed_id, "force": True})
        assert needless_force.status_code == 422
        assert fixture.config.updates == updates


def test_plan_is_actor_bound_expires_and_detects_revision_change_without_side_effect(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    clock = [1_767_326_400.0]
    fixture.controls.network._now = lambda: clock[0]
    with TestClient(app) as client:
        first_headers = bearer(create_session(client))
        plan = operation(client, first_headers, client.post(PREFIX + "/network/dns/tests", headers=first_headers, json={"servers": ["1.0.0.1"]}))["result"]["plan"]
        second_headers = bearer(create_session(client))
        before = fixture.config.updates
        cross_actor = client.post(PREFIX + "/network/dns/commits", headers=second_headers, json={"planId": plan["id"], "force": False})
        assert cross_actor.status_code == 404
        assert fixture.config.updates == before
        clock[0] += 61
        expired = client.post(PREFIX + "/network/dns/commits", headers=first_headers, json={"planId": plan["id"], "force": False})
        assert expired.status_code == 409
        assert expired.json()["error"]["code"] == "STATE_CONFLICT"
        assert fixture.config.updates == before

        clock[0] += 1
        fresh = operation(client, first_headers, client.post(PREFIX + "/network/dns/tests", headers=first_headers, json={"servers": ["1.0.0.2"]}))["result"]["plan"]
        changed = client.patch(PREFIX + "/network/socks5", headers=first_headers, json={"enabled": False})
        assert changed.status_code == 200
        writes = fixture.config.updates
        stale = client.post(PREFIX + "/network/dns/commits", headers=first_headers, json={"planId": fresh["id"], "force": False})
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "REVISION_CONFLICT"
        assert fixture.config.updates == writes


def test_socks_plan_never_exposes_credentials_and_secret_only_rotation_keeps_public_revision(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before = client.get(PREFIX + "/network", headers=headers).json()["data"]
        assert_secret_safe(before)
        tested = operation(client, headers, client.post(
            PREFIX + "/network/socks5/tests", headers=headers,
            json={"url": "socks5://username-marker:new-password-marker@proxy.invalid:1080"},
        ))
        assert_secret_safe(tested)
        plan = tested["result"]["plan"]
        assert plan["tested"]["configured"] is True
        assert plan["tested"]["maskedUrl"] == "socks5://***:***@proxy.invalid:1080"
        committed = client.post(PREFIX + "/network/socks5/commits", headers=headers, json={"planId": plan["id"], "force": False})
        assert committed.status_code == 200, committed.text
        after = committed.json()["data"]
        assert_secret_safe(after)
        assert after["revision"] == before["revision"]
        assert "username-marker" in fixture.config.value["network"]["socks5"]["url"]


def test_network_settings_sync_cache_clear_and_socks_state_validation(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        cache = client.get(PREFIX + "/network/dns/cache?page=1&pageSize=1", headers=headers)
        assert cache.status_code == 200
        assert cache.json()["data"]["items"][0]["expiresAt"].endswith("Z")
        assert cache.json()["meta"] == {**cache.json()["meta"], "page": 1, "pageSize": 1, "total": 1, "hasNext": False}
        cleared = client.delete(PREFIX + "/network/dns/cache", headers=headers)
        assert cleared.status_code == 204
        assert fixture.gateway.cache == []
        synced = client.post(PREFIX + "/network/dns/actions/sync-system", headers=headers)
        assert synced.status_code == 200
        assert synced.json()["data"]["dns"]["servers"] == ["9.9.9.9"]
        disabled = client.patch(PREFIX + "/network/socks5", headers=headers, json={"enabled": False})
        assert disabled.status_code == 200
        fixture.config.update(lambda root: root["network"].__setitem__("socks5", {"enabled": False, "url": ""}))
        writes = fixture.config.updates
        invalid = client.patch(PREFIX + "/network/socks5", headers=headers, json={"enabled": True})
        assert invalid.status_code == 422
        assert fixture.config.updates == writes


def test_dns_cache_ips_sanitize_credentials_without_public_text_false_positives(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    public_values = [
        "192.0.2.10", "monkey", "hockey", "donkey", "Bearer routing-mode",
        "Basic routing-mode", "bearer support-enabled", "Basic request-routing",
        "Bearer ordinary.word", "Basic routing mode", "Bearer support is enabled",
        "Bearer landmarker", "Bearer OrdinaryMode", 'Bearer "routing-mode"',
        "ordinary monkey hockey donkey; Bearer routing-mode",
    ]
    jwt_credential = ".".join(("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "signature"))
    credential_inputs = [
        ("generic-token-marker", "token=generic-token-marker"),
        ("camel-token-marker", "apiToken=camel-token-marker"),
        ("snake-token-marker", "api_token=snake-token-marker"),
        ("upper-token-marker", "API_TOKEN=upper-token-marker"),
        ("generic-key-marker", "key=generic-key-marker"),
        ("camel-key-marker", "apiKey=camel-key-marker"),
        ("snake-key-marker", "api_key=snake-key-marker"),
        ("upper-key-marker", "API_KEY=upper-key-marker"),
        ("generic-secret-marker", "secret=generic-secret-marker"),
        ("camel-secret-marker", "clientSecret=camel-secret-marker"),
        ("snake-secret-marker", "client_secret=snake-secret-marker"),
        ("upper-secret-marker", "CLIENT_SECRET=upper-secret-marker"),
        ("generic-credential-marker", "credential=generic-credential-marker"),
        ("camel-credential-marker", "serviceCredential=camel-credential-marker"),
        ("snake-credential-marker", "service_credential=snake-credential-marker"),
        ("upper-credential-marker", "SERVICE_CREDENTIAL=upper-credential-marker"),
        ("authorization-header-marker", "Authorization: Bearer authorization-header-marker"),
        ("cookie-header-marker", "Cookie: cookie-header-marker"),
        ("bearer-token-marker", "Bearer bearer.opaque.token-marker"),
        ("abc-def-ghi", "Bearer abc-def-ghi"),
        ("abc-def-ghi", "Basic abc-def-ghi"),
        ("abcdefghijklmnop-qrst", "Bearer abcdefghijklmnop-qrst"),
        ("abcdefghijklmnopqrstuvwxyzabcdef", "Bearer abcdefghijklmnopqrstuvwxyzabcdef"),
        ("abcdefg1", "Bearer abcdefg1"),
        ("AbcdefghijklmnoP", "Bearer AbcdefghijklmnoP"),
        (jwt_credential, "Bearer " + jwt_credential),
        ("access-token", "Bearer access-token"),
        ("marker", "Bearer marker"),
        ("dXNlcjpwYXNzd29yZA==", "Basic dXNlcjpwYXNzd29yZA=="),
        ("url-user-marker", "https://url-user-marker:url-password-marker@dns.invalid/result"),
        ("url-password-marker", "https://url-user-marker:url-password-marker@dns.invalid/result"),
    ]
    fixture.gateway.cache[0]["ips"] = public_values + [value for _, value in credential_inputs]
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(PREFIX + "/network/dns/cache", headers=headers)
    assert response.status_code == 200, response.text
    returned = response.json()["data"]["items"][0]["ips"]
    assert returned[:len(public_values)] == public_values
    assert len(returned) == len(public_values) + len(credential_inputs)
    credential_outputs = returned[len(public_values):]
    for (marker, credential), output in zip(credential_inputs, credential_outputs):
        assert output != credential
        assert marker not in output


def test_monitor_patch_exact_channels_history_and_async_run_are_secret_safe(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        current = client.get(PREFIX + "/network/monitor", headers=headers)
        assert current.status_code == 200
        revision = current.json()["data"]["revision"]
        updated = client.patch(
            PREFIX + "/network/monitor", headers={**headers, "If-Match": revision},
            json={
                "enabled": True, "intervalSeconds": 15, "dns": True,
                "core": {"openai": True},
                "channels": {"enabled": True, "byChannel": {"api:example": True}},
            },
        )
        assert updated.status_code == 200, updated.text
        data = updated.json()["data"]
        assert data["intervalSeconds"] == 15
        assert data["channels"]["byChannel"] == {"api:example": True}
        before = fixture.config.updates
        unknown = client.patch(PREFIX + "/network/monitor", headers=headers, json={"channels": {"byChannel": {"example": True}}})
        assert unknown.status_code == 404
        assert fixture.config.updates == before
        history = client.get(PREFIX + "/network/monitor/checks", headers=headers)
        assert history.status_code == 200
        assert_secret_safe(history.json())
        detail = history.json()["data"]["items"][0]["detail"]
        for business_text in (
            "Basic business words", "monkey", "hockey", "turkey", "donkey",
            "passkey", "keyboard",
        ):
            assert business_text in detail
        assert "<redacted>" in detail
        run = operation(client, headers, client.post(PREFIX + "/network/monitor/actions/run", headers=headers))
        assert run["status"] == "succeeded"
        assert_secret_safe(run)


def test_monitor_history_preserves_auth_prose_and_redacts_credentials(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    basic = base64.b64encode(b"history-user:history-password").decode("ascii")
    fixture.gateway.history = [
        {
            "key": f"check-{index}", "label": text, "category": "dns",
            "ok": True, "detail": text, "latency_ms": index,
            "checked_at": 1_767_326_400_000 + index,
        }
        for index, text in enumerate(PUBLIC_AUTH_PROSE)
    ] + [{
        "key": "credential-check", "label": "Bearer abc-def-ghi",
        "category": "dns", "ok": False,
        "detail": (
            "Authorization: Bearer history-auth-marker; "
            "Cookie=history-cookie-marker; apiToken=history-token-marker; "
            f"Basic {basic}; Bearer abcdefg1; "
            "https://history-user-marker:history-password-marker@dns.invalid/result"
        ),
        "latency_ms": None, "checked_at": 1_767_326_400_100,
    }]

    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(PREFIX + "/network/monitor/checks", headers=headers)

    assert response.status_code == 200, response.text
    items = response.json()["data"]["items"]
    for text, item in zip(PUBLIC_AUTH_PROSE, items):
        assert item["label"] == text
        assert item["detail"] == text
    credential_item = items[-1]
    assert credential_item["label"] == "Bearer <redacted>"
    for marker in (
        "history-auth-marker", "history-cookie-marker", "history-token-marker",
        "history-user-marker", "history-password-marker", basic, "abcdefg1",
    ):
        assert marker not in response.text
    assert "<redacted>" in credential_item["detail"]


def test_dns_and_socks_test_results_recursively_sanitize_auth_values(tmp_path, monkeypatch):
    app, _runtime, fixture = build_p6_app(tmp_path)

    def dns_result(_servers):
        return {
            "ok": True,
            "message": "Bearer routing-mode",
            "nested": {
                "values": ["Basic request-routing", ("Bearer ordinary.word",)],
                "apiToken": "dns-result-token-marker",
                "key": "dns-result-key-marker",
                "detail": "Basic routing mode; Bearer abc-def-ghi",
            },
        }

    async def socks_result(_url):
        return {
            "ok": True,
            "url": "socks5://socks-user-marker:socks-password-marker@proxy.invalid:1080",
            "display_url": "socks5://socks-user-marker:socks-password-marker@proxy.invalid:1080",
            "message": "bearer support-enabled",
            "nested": [{
                "prose": "Bearer support is enabled",
                "clientSecret": "socks-result-secret-marker",
                "authorization": "Basic dXNlcjpwYXNzd29yZA==",
                "detail": "Bearer AbcdefghijklmnoP",
            }],
        }

    monkeypatch.setattr(fixture.gateway, "test_dns", dns_result)
    monkeypatch.setattr(fixture.gateway, "test_socks5", socks_result)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        dns = operation(client, headers, client.post(
            PREFIX + "/network/dns/tests", headers=headers,
            json={"servers": ["1.1.1.1"]},
        ))["result"]["plan"]["result"]
        socks = operation(client, headers, client.post(
            PREFIX + "/network/socks5/tests", headers=headers,
            json={"url": "socks5://input-user:input-password@proxy.invalid:1080"},
        ))["result"]["plan"]["result"]

    assert dns["message"] == "Bearer routing-mode"
    assert dns["nested"]["values"] == ["Basic request-routing", ["Bearer ordinary.word"]]
    assert dns["nested"]["apiToken"] == "<redacted>"
    assert dns["nested"]["key"] == "<redacted>"
    assert dns["nested"]["detail"] == "Basic routing mode; Bearer <redacted>"
    assert socks["message"] == "bearer support-enabled"
    assert socks["nested"][0]["prose"] == "Bearer support is enabled"
    assert socks["nested"][0]["clientSecret"] == "<redacted>"
    assert socks["nested"][0]["authorization"] == "<redacted>"
    assert socks["nested"][0]["detail"] == "Bearer <redacted>"
    encoded = json.dumps({"dns": dns, "socks": socks})
    for marker in (
        "dns-result-token-marker", "dns-result-key-marker",
        "socks-result-secret-marker", "socks-user-marker", "socks-password-marker",
        "dXNlcjpwYXNzd29yZA==", "AbcdefghijklmnoP",
    ):
        assert marker not in encoded


def test_monitor_operation_preserves_identifiers_and_sanitizes_nested_values(tmp_path, monkeypatch):
    app, _runtime, fixture = build_p6_app(tmp_path)

    async def monitor_result():
        return [{
            "key": "dns-route-key", "category": "dns",
            "channelKey": "api:channel-key", "keyId": "public-key-id",
            "keyCount": 2, "label": "Bearer routing-mode", "ok": False,
            "detail": "Basic request-routing",
            "nested": {
                "key": "nested-public-key", "channelKey": "nested-channel-key",
                "values": ["Bearer ordinary.word", ("Basic routing mode",)],
                "api_token": "monitor-token-marker",
                "cookie": "monitor-cookie-marker",
                "url": "https://monitor-user-marker:monitor-password-marker@monitor.invalid/result",
                "authorization": "Bearer abcdefghijklmno-p",
            },
        }]

    monkeypatch.setattr(fixture.gateway, "run_monitor", monitor_result)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        result = operation(
            client, headers,
            client.post(PREFIX + "/network/monitor/actions/run", headers=headers),
        )["result"]["checks"][0]

    assert result["key"] == "dns-route-key"
    assert result["category"] == "dns"
    assert result["channelKey"] == "api:channel-key"
    assert result["keyId"] == "public-key-id"
    assert result["keyCount"] == 2
    assert result["label"] == "Bearer routing-mode"
    assert result["detail"] == "Basic request-routing"
    assert result["nested"]["key"] == "nested-public-key"
    assert result["nested"]["channelKey"] == "nested-channel-key"
    assert result["nested"]["values"] == [
        "Bearer ordinary.word", ["Basic routing mode"],
    ]
    assert result["nested"]["api_token"] == "<redacted>"
    assert result["nested"]["cookie"] == "<redacted>"
    assert result["nested"]["authorization"] == "<redacted>"
    encoded = json.dumps(result)
    for marker in (
        "monitor-token-marker", "monitor-cookie-marker", "monitor-user-marker",
        "monitor-password-marker", "abcdefghijklmno-p",
    ):
        assert marker not in encoded


def test_secret_only_concurrent_change_invalidates_plan_without_changing_public_revision(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before = client.get(PREFIX + "/network", headers=headers).json()["data"]["revision"]
        tested = operation(client, headers, client.post(
            PREFIX + "/network/socks5/tests", headers=headers,
            json={"url": "socks5://username-marker:tested-password-marker@proxy.invalid:1080"},
        ))
        plan_id = tested["result"]["plan"]["id"]
        concurrent_url = "socks5://other-user-marker:concurrent-password-marker@proxy.invalid:1080"
        fixture.config.update(lambda root: root["network"].__setitem__("socks5", {"enabled": True, "url": concurrent_url}))
        assert client.get(PREFIX + "/network", headers=headers).json()["data"]["revision"] == before
        writes = fixture.config.updates
        conflict = client.post(PREFIX + "/network/socks5/commits", headers=headers, json={"planId": plan_id, "force": False})
        assert conflict.status_code == 409
        assert conflict.json()["error"]["code"] == "REVISION_CONFLICT"
        assert fixture.config.updates == writes
        assert fixture.config.value["network"]["socks5"]["url"] == concurrent_url


def test_dns_public_url_query_redaction_has_no_business_word_false_positives(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    fixture.config.update(lambda root: root["network"]["dns"].__setitem__(
        "servers", ["https://user-marker:pass-marker@dns.invalid/query?monkey=banana&apiToken=query-marker"],
    ))
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        data = client.get(PREFIX + "/network", headers=headers).json()["data"]
        encoded = json.dumps(data, ensure_ascii=False)
        for marker in ("user-marker", "pass-marker", "query-marker"):
            assert marker not in encoded
        assert "monkey=banana" in data["dns"]["servers"][0]


def test_probe_exception_is_terminal_operation_failure_without_raw_error(tmp_path, monkeypatch):
    app, _runtime, fixture = build_p6_app(tmp_path)
    def fail(_servers):
        raise RuntimeError("accessToken=test-marker-dns")
    monkeypatch.setattr(fixture.gateway, "test_dns", fail)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        result = operation(client, headers, client.post(PREFIX + "/network/dns/tests", headers=headers, json={"servers": ["1.1.1.1"]}))
        assert result["status"] == "failed"
        assert result["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert_secret_safe(result)
        assert not fixture.controls.network._plans

from __future__ import annotations

import copy
import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from src.management_control import ManagementError, ManagementErrorCode
from src.management_control.observability.common import telegram_context
from src.management_control.operations import OperationStatus
from src.management_control.system import ContentBlacklistControl
from src.tests.management_system_network_support import (
    FakeConfig,
    bearer,
    build_p6_app,
    create_session,
)


PREFIX = "/api/management/v1"


def _chain_strings(exc: BaseException) -> list[str]:
    values: list[str] = []
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.append(str(current))
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                pending.append(linked)
    return values


def test_blacklist_revision_tracks_order_visibility_and_only_public_projection(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    fixture.registry.items = [
        SimpleNamespace(key="api:first", display_name="first", type="api"),
        SimpleNamespace(key="api:second", display_name="second", type="api"),
    ]
    fixture.config.update(lambda cfg: cfg.__setitem__("contentBlacklist", {
        "default": ["base"],
        "byChannel": {"api:first": ["one"], "api:second": ["two"]},
    }))
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        ordered = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        assert [row["channelId"] for row in ordered["byChannel"]] == ["api:first", "api:second"]

        fixture.config.update(lambda cfg: cfg["contentBlacklist"].__setitem__(
            "byChannel", {"api:second": ["two"], "api:first": ["one"]},
        ))
        reordered = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        assert [row["channelId"] for row in reordered["byChannel"]] == ["api:second", "api:first"]
        assert reordered["revision"] != ordered["revision"]
        writes = fixture.config.updates
        stale = client.post(
            PREFIX + "/content-blacklist/default",
            headers={**headers, "If-Match": ordered["revision"]}, json={"term": "stale"},
        )
        assert stale.status_code == 409
        assert fixture.config.updates == writes

        fixture.config.update(lambda cfg: cfg.__setitem__("contentBlacklist", {
            "default": [], "byChannel": {"alias": ["visible"]},
        }))
        fixture.registry.items = []
        orphan = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        assert orphan["byChannel"] == [{"channelId": "alias", "terms": ["visible"]}]
        fixture.registry.items = [SimpleNamespace(key="api:alias", display_name="alias", type="api")]
        canonical = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        assert canonical["byChannel"] == [{"channelId": "api:alias", "terms": ["visible"]}]
        assert canonical["revision"] != orphan["revision"]
        stale_visibility = client.post(
            PREFIX + "/content-blacklist/default",
            headers={**headers, "If-Match": orphan["revision"]}, json={"term": "stale"},
        )
        assert stale_visibility.status_code == 409

        before_empty = canonical["revision"]
        fixture.config.update(
            lambda cfg: cfg["contentBlacklist"]["byChannel"].__setitem__("private-empty", [])
        )
        after_empty = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        assert after_empty["revision"] == before_empty
        assert all(row["channelId"] != "private-empty" for row in after_empty["byChannel"])


def test_blacklist_orphan_and_slash_channel_are_listable_and_deletable(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    orphan_id = "orphan/a"
    orphan_term = "old/term"
    live_id = "api:a/b"
    live_term = "new/term"
    fixture.config.update(lambda cfg: cfg.__setitem__("contentBlacklist", {
        "default": [], "byChannel": {orphan_id: [orphan_term]},
    }))
    fixture.registry.items.append(
        SimpleNamespace(key=live_id, display_name="a/b", type="api")
    )
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        listed = client.get(PREFIX + "/content-blacklist", headers=headers).json()["data"]
        assert listed["byChannel"] == [{"channelId": orphan_id, "terms": [orphan_term]}]

        removed = client.delete(
            PREFIX + "/content-blacklist/channels/"
            + quote(orphan_id, safe="") + "/" + quote(orphan_term, safe=""),
            headers=headers,
        )
        assert removed.status_code == 204, removed.text
        assert orphan_id not in fixture.config.value["contentBlacklist"]["byChannel"]

        added = client.post(
            PREFIX + "/content-blacklist/channels/" + quote(live_id, safe=""),
            headers=headers, json={"term": live_term},
        )
        assert added.status_code == 201, added.text
        assert added.json()["data"]["byChannel"] == [
            {"channelId": live_id, "terms": [live_term]},
        ]
        deleted = client.delete(
            PREFIX + "/content-blacklist/channels/"
            + quote(live_id, safe="") + "/" + quote(live_term, safe=""),
            headers=headers,
        )
        assert deleted.status_code == 204, deleted.text
        assert live_id not in fixture.config.value["contentBlacklist"]["byChannel"]


class _InterleavingConfig(FakeConfig):
    def __init__(self) -> None:
        super().__init__()
        self.blacklist_waiting = threading.Event()

    @contextmanager
    def serialized_updates(self):
        if threading.current_thread().name == "blacklist-writer":
            self.blacklist_waiting.set()
        with self._lock:
            yield


class _LockedRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.items = [SimpleNamespace(key="api:example", display_name="example", type="api")]

    def all_channels(self):
        with self._lock:
            return list(self.items)


def test_blacklist_and_channel_writer_interleaving_has_one_config_to_registry_order():
    config = _InterleavingConfig()
    registry = _LockedRegistry()
    control = ContentBlacklistControl(config=config, registry=registry)
    context = telegram_context("lock-order")
    config_held = threading.Event()
    channel_done = threading.Event()
    errors: list[BaseException] = []
    acquired_registry: list[bool] = []

    def channel_writer() -> None:
        try:
            with config.serialized_updates():
                config_held.set()
                assert config.blacklist_waiting.wait(timeout=2)
                acquired = registry._lock.acquire(timeout=1)
                acquired_registry.append(acquired)
                if acquired:
                    registry._lock.release()
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            channel_done.set()

    def blacklist_writer() -> None:
        try:
            assert config_held.wait(timeout=2)
            control.add_channel(context, "api:example", "term")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    channel = threading.Thread(target=channel_writer, name="channel-writer")
    blacklist = threading.Thread(target=blacklist_writer, name="blacklist-writer")
    channel.start()
    blacklist.start()
    channel.join(timeout=3)
    blacklist.join(timeout=3)
    assert channel_done.is_set()
    assert not channel.is_alive() and not blacklist.is_alive()
    assert not errors
    assert acquired_registry == [True]
    assert config.value["contentBlacklist"]["byChannel"]["api:example"] == ["term"]


STRICT_BODY_CASES = (
    ("PATCH", "/settings/timeouts", {"connect": "11"}),
    ("PATCH", "/settings/timeouts", {"connect": True}),
    ("PATCH", "/settings/timeouts", {"connect": 1.5}),
    ("PATCH", "/settings/concurrency", {"enabled": "false"}),
    ("PATCH", "/settings/concurrency", {"enabled": 0}),
    ("PATCH", "/settings/concurrency", {"enabled": []}),
    ("PATCH", "/settings/quota-monitor", {"thresholdPercent": "50.5"}),
    ("PATCH", "/settings/quota-monitor", {"thresholdPercent": True}),
    ("PATCH", "/settings/scoring", {"emaAlpha": "0.5"}),
    ("PATCH", "/settings/error-cooldown", {"errorWindows": ["1"]}),
    ("PATCH", "/settings/retry", {"transient": []}),
    ("PATCH", "/settings/retry", {"transient": {"backoffSeconds": "1,2"}}),
    ("PATCH", "/settings/notifications", {"events": []}),
    ("POST", "/content-blacklist/default", {"term": 12}),
    ("POST", "/content-blacklist/default", {"term": ["term"]}),
    ("POST", "/network/dns/tests", {"servers": "1.1.1.1"}),
    ("POST", "/network/dns/tests", {"servers": [1]}),
    ("POST", "/network/socks5/tests", {"url": 123}),
    ("POST", "/network/dns/commits", {"planId": 123, "force": False}),
    ("POST", "/network/dns/commits", {"planId": "missing", "force": "false"}),
    ("PATCH", "/network/socks5", {"enabled": "false"}),
    ("PATCH", "/network/monitor", {"intervalSeconds": "10"}),
    ("PATCH", "/network/monitor", {"core": {"openai": 1}}),
    ("PATCH", "/network/monitor", {"channels": {"byChannel": {"api:example": "true"}}}),
)


@pytest.mark.parametrize(("method", "path", "payload"), STRICT_BODY_CASES)
def test_all_p6_request_scalar_shapes_are_strict_and_side_effect_free(
    tmp_path, method, path, payload,
):
    app, runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before_config = copy.deepcopy(fixture.config.value)
        before_updates = fixture.config.updates
        before_audit = fixture.audit.snapshot()
        before_operations = copy.deepcopy(runtime.operations._items)
        before_events = copy.deepcopy(fixture.gateway.events)
        response = client.request(method, PREFIX + path, headers=headers, json=payload)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
        assert fixture.config.value == before_config
        assert fixture.config.updates == before_updates
        assert fixture.audit.snapshot() == before_audit
        assert runtime.operations._items == before_operations
        assert fixture.gateway.events == before_events


def test_notifications_expose_and_patch_all_twelve_authoritative_events(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before = client.get(PREFIX + "/settings/notifications", headers=headers).json()["data"]
        assert list(before["events"]) == [
            "channelPermanent", "channelRecovered", "quotaDisabled", "quotaResumed",
            "quotaCooldown", "oauthRefreshed", "oauthRefreshFailed", "noChannels",
            "openaiStoreSaveFailed", "statusAlert", "appUpdate", "networkMonitor",
        ]
        changed = client.patch(
            PREFIX + "/settings/notifications",
            headers={**headers, "If-Match": before["revision"]},
            json={"events": {"statusAlert": False, "appUpdate": False}},
        )
        assert changed.status_code == 200, changed.text
        data = changed.json()["data"]
        assert data["events"]["statusAlert"] is False
        assert data["events"]["appUpdate"] is False
        assert data["revision"] != before["revision"]
        stored = fixture.config.value["notifications"]["events"]
        assert stored["status_alert"] is False
        assert stored["app_update"] is False
        assert client.get(PREFIX + "/settings/notifications", headers=headers).json()["data"] == data


@pytest.mark.parametrize("payload", ({"core": {}}, {"channels": {}}, {"channels": {"byChannel": {}}}))
def test_network_semantically_empty_nested_patch_is_422_and_side_effect_free(tmp_path, payload):
    app, runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        before = (
            copy.deepcopy(fixture.config.value), fixture.config.updates,
            fixture.audit.snapshot(), copy.deepcopy(runtime.operations._items),
            copy.deepcopy(fixture.gateway.events),
        )
        response = client.patch(PREFIX + "/network/monitor", headers=headers, json=payload)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
        after = (
            fixture.config.value, fixture.config.updates,
            fixture.audit.snapshot(), runtime.operations._items, fixture.gateway.events,
        )
        assert after == before


def test_network_openapi_marks_dns_candidates_write_only_and_category_is_finite(tmp_path):
    app, _runtime, _fixture = build_p6_app(tmp_path)
    schema = app.openapi()
    components = schema["components"]["schemas"]
    servers = components["DnsTestRequest"]["properties"]["servers"]
    assert servers["writeOnly"] is True
    assert servers["examples"] == [["https://dns.example/dns-query"]]
    assert "@" not in json.dumps(servers)
    category = components["NetworkCheckData"]["properties"]["category"]
    enum_name = category["$ref"].rsplit("/", 1)[-1]
    assert set(components[enum_name]["enum"]) == {"dns", "socks5", "channel", "core"}


def test_invalid_stored_monitor_category_is_stable_422(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    fixture.gateway.history[0]["category"] = "credential-shaped-unknown"
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(PREFIX + "/network/monitor/checks", headers=headers)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["fields"][0]["path"] == "category"


def test_monitor_run_preserves_public_identifiers_and_sanitizes_untrusted_matrix(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    detail = (
        "token=generic-token key=generic-key secret=generic-secret "
        "api_token=snake-token api_key=snake-key sessionSecret=camel-secret "
        "TOKEN=upper-token CREDENTIAL=upper-credential "
        "url=https://url-user:url-pass@host.invalid/x?apiToken=query-secret "
        "Bearer opaque.secret.token Basic dXNlcjpwYXNz "
        "monkey hockey donkey passkey keyboard Bearer docs Basic business"
    )

    async def run_monitor():
        return [{
            "key": "api:example/check", "category": "channel", "label": "Example",
            "ok": False, "detail": detail, "error": "refreshToken=error-secret",
            "value": "clientSecret=value-secret", "latencyMilliseconds": None,
        }]

    fixture.gateway.run_monitor = run_monitor
    fixture.gateway.history[0].update({
        "key": "api:example/check", "category": "channel", "detail": detail,
    })
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        history = client.get(PREFIX + "/network/monitor/checks", headers=headers)
        assert history.status_code == 200, history.text
        history_check = history.json()["data"]["items"][0]
        assert history_check["key"] == "api:example/check"
        assert history_check["category"] == "channel"
        started = client.post(PREFIX + "/network/monitor/actions/run", headers=headers)
        assert started.status_code == 202, started.text
        operation_id = started.json()["data"]["id"]
        result = client.get(PREFIX + "/operations/" + operation_id, headers=headers).json()["data"]
        assert result["status"] == "succeeded"
        check = result["result"]["checks"][0]
        assert check["key"] == "api:example/check"
        assert check["category"] == "channel"
        encoded = json.dumps(check, ensure_ascii=False)
        for secret in (
            "generic-token", "generic-key", "generic-secret", "snake-token",
            "snake-key", "camel-secret", "upper-token", "upper-credential",
            "url-user", "url-pass", "query-secret", "opaque.secret.token",
            "dXNlcjpwYXNz", "error-secret", "value-secret",
        ):
            assert secret not in encoded
            assert secret not in json.dumps(history_check, ensure_ascii=False)
        for ordinary in (
            "monkey", "hockey", "donkey", "passkey", "keyboard",
            "Bearer docs", "Basic business",
        ):
            assert ordinary in check["detail"]
            assert ordinary in history_check["detail"]


def test_dns_validation_and_worker_launch_errors_have_no_credential_chain_and_are_audited(tmp_path):
    app, runtime, fixture = build_p6_app(tmp_path)
    context = telegram_context("network-boundary")
    secret_url = "https://user-secret:password-secret@dns.invalid/dns-query?apiToken=query-secret"

    def invalid_dns(_servers):
        raise ValueError("invalid candidate " + secret_url)

    fixture.gateway.normalize_dns = invalid_dns
    with pytest.raises(ManagementError) as invalid:
        fixture.controls.network.start_dns_test(context, [secret_url])
    assert invalid.value.code is ManagementErrorCode.VALIDATION_FAILED
    assert all("secret" not in value for value in _chain_strings(invalid.value))
    assert invalid.value.__cause__ is None and invalid.value.__context__ is None

    fixture.gateway.normalize_dns = lambda servers: servers

    def fail_doh(_servers):
        raise RuntimeError("DoH query failed for " + secret_url)

    fixture.gateway.test_dns = fail_doh
    failed_probe = fixture.controls.network.start_dns_test(context, ["https://dns.invalid/dns-query"])
    failed_probe = runtime.operations.get(context, failed_probe.id)
    assert failed_probe.status is OperationStatus.FAILED
    assert "user-secret" not in str(failed_probe)
    assert "password-secret" not in str(failed_probe)
    assert "query-secret" not in str(failed_probe)

    fixture.controls.network._start_worker = lambda _worker: (_ for _ in ()).throw(
        RuntimeError("apiToken=launch-secret")
    )
    starters = (
        ("network.dns.test", lambda: fixture.controls.network.start_dns_test(context, ["1.1.1.1"])),
        ("network.socks5.test", lambda: fixture.controls.network.start_socks5_test(context, "socks5://proxy.invalid:1080")),
        ("network.monitor.run", lambda: fixture.controls.network.run_monitor(context)),
    )
    for action, starter in starters:
        prior = len([row for row in fixture.audit.snapshot() if row.action == action])
        with pytest.raises(ManagementError) as failed:
            starter()
        assert failed.value.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
        assert failed.value.operation_id
        assert all("launch-secret" not in value for value in _chain_strings(failed.value))
        terminal = runtime.operations.get(context, failed.value.operation_id)
        assert terminal.status is OperationStatus.FAILED
        records = [row for row in fixture.audit.snapshot() if row.action == action]
        assert len(records) == prior + 1
        assert records[-1].actor == context.actor.subject_id
        assert records[-1].target in {"dns", "socks5", "monitor"}
        assert records[-1].result == "failed"

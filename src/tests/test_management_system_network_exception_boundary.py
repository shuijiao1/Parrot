from __future__ import annotations

import asyncio
import copy
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from src.management_auth import AuthMethod, ManagementPrincipal
from src.management_control import (
    BoundedAuditSink,
    ManagementContext,
    ManagementError,
    ManagementErrorCode,
)
from src.management_control.operations import OperationStatus
from src.management_control.system import ContentBlacklistControl, SettingsControl
from src.tests.management_system_network_support import (
    FakeConfig,
    FakeRegistry,
    bearer,
    build_p6_app,
    create_session,
)


PREFIX = "/api/management/v1"
MARKER = "exception-boundary-apiToken-credential"


def _management_context() -> ManagementContext:
    return ManagementContext(
        request_id="exception-boundary",
        actor=ManagementPrincipal.administrator(
            subject_id="boundary-admin",
            auth_method=AuthMethod.MANAGEMENT_KEY,
            session_id="boundary-session",
        ),
    )


def _telegram_context() -> ManagementContext:
    return ManagementContext(
        request_id="telegram:boundary",
        actor=ManagementPrincipal.administrator(
            subject_id="telegram:42",
            auth_method=AuthMethod.TELEGRAM_ADMIN,
        ),
    )


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


def _assert_safe_dependency(exc: ManagementError) -> None:
    assert exc.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
    assert exc.retryable is True
    assert MARKER not in str(exc)
    assert all(MARKER not in value for value in _chain_strings(exc))
    assert exc.__cause__ is None
    assert exc.__context__ is None


def _assert_failed_audit(audit, *, action: str, prior: int = 0) -> None:
    records = [row for row in audit.snapshot() if row.action == action]
    assert len(records) == prior + 1
    assert records[-1].result == "failed"
    assert MARKER not in repr(records[-1])


class _StagedConfig(FakeConfig):
    def __init__(self, stage: str) -> None:
        super().__init__()
        self.stage = stage
        self.get_calls = 0
        self.failure = RuntimeError(f"config {stage} failed {MARKER}")

    def get(self):
        self.get_calls += 1
        if self.stage == "get" and self.get_calls == 1:
            raise self.failure
        if self.stage == "post_get" and self.get_calls == 2:
            raise self.failure
        return super().get()

    def update(self, mutator, **kwargs):
        if self.stage == "update":
            raise self.failure
        return super().update(mutator, **kwargs)

    @contextmanager
    def serialized_updates(self):
        if self.stage == "enter":
            raise self.failure
        try:
            with super().serialized_updates():
                yield
        finally:
            if self.stage == "exit":
                raise self.failure


def test_settings_get_config_and_reader_failures_are_stable_http_and_direct(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))

        failure = RuntimeError(f"settings get failed {MARKER}")
        fixture.config.get = lambda: (_ for _ in ()).throw(failure)
        response = client.get(PREFIX + "/settings/timeouts", headers=headers)
        assert response.status_code == 503, response.text
        assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert MARKER not in response.text

    config = FakeConfig()
    control = SettingsControl(config=config)
    reader_failure = RuntimeError(f"settings reader failed {MARKER}")
    control._timeouts = lambda _cfg: (_ for _ in ()).throw(reader_failure)
    with pytest.raises(ManagementError) as caught:
        control.get(_management_context(), "timeouts")
    _assert_safe_dependency(caught.value)

    with pytest.raises(ManagementError) as missing:
        control.get(_management_context(), "not-a-resource")
    assert missing.value.code is ManagementErrorCode.RESOURCE_NOT_FOUND


@pytest.mark.parametrize(
    ("stage", "expected_updates"),
    (
        ("enter", 0),
        ("get", 0),
        ("update", 0),
        ("post_get", 1),
        ("post_reader", 1),
        ("exit", 1),
    ),
)
def test_settings_management_update_dependency_matrix_is_safe_and_audited(
    stage, expected_updates,
):
    config = _StagedConfig(stage)
    audit = BoundedAuditSink()
    control = SettingsControl(config=config, audit_sink=audit)
    if stage == "post_reader":
        original = control._timeouts
        calls = 0

        def reader(cfg):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise config.failure
            return original(cfg)

        control._timeouts = reader

    before = copy.deepcopy(config.value)
    with pytest.raises(ManagementError) as caught:
        control.update_timeouts(_management_context(), {"connect": 11})
    _assert_safe_dependency(caught.value)
    assert config.updates == expected_updates
    if expected_updates == 0:
        assert config.value == before
    else:
        assert config.value["timeouts"]["connect"] == 11
    _assert_failed_audit(audit, action="settings.timeouts.update")


@pytest.mark.parametrize(
    ("path", "payload", "action"),
    (
        ("/settings/timeouts", {"connect": 11}, "settings.timeouts.update"),
        (
            "/content-blacklist/default", {"term": "blocked-term"},
            "content_blacklist.default.add",
        ),
    ),
)
def test_system_mutation_dependency_failure_is_stable_http(
    tmp_path, path, payload, action,
):
    app, _runtime, fixture = build_p6_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        raw = RuntimeError(f"system mutation HTTP failed {MARKER}")
        fixture.config.update = lambda _mutator: (
            _ for _ in ()
        ).throw(raw)
        method = "patch" if path.startswith("/settings/") else "post"
        response = getattr(client, method)(
            PREFIX + path, headers=headers, json=payload,
        )
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert MARKER not in response.text
    _assert_failed_audit(fixture.audit, action=action)


def test_settings_telegram_approval_actor_uses_safe_management_boundary():
    config = _StagedConfig("update")
    audit = BoundedAuditSink()
    control = SettingsControl(config=config, audit_sink=audit)
    context = ManagementContext(
        request_id="approval-boundary",
        actor=ManagementPrincipal.administrator(
            subject_id="approval-admin",
            auth_method=AuthMethod.TELEGRAM_APPROVAL,
            session_id="approval-session",
        ),
    )
    with pytest.raises(ManagementError) as caught:
        control.update_timeouts(context, {"connect": 11})
    _assert_safe_dependency(caught.value)
    _assert_failed_audit(audit, action="settings.timeouts.update")


def test_settings_telegram_write_preserves_raw_exception_identity_and_no_audit():
    config = FakeConfig()
    audit = BoundedAuditSink()
    control = SettingsControl(config=config, audit_sink=audit)
    raw = RuntimeError(f"telegram settings raw {MARKER}")
    config.update = lambda _mutator: (_ for _ in ()).throw(raw)

    with pytest.raises(RuntimeError) as caught:
        control.update_timeouts(_telegram_context(), {"connect": 11})
    assert caught.value is raw
    assert str(caught.value) == f"telegram settings raw {MARKER}"
    assert audit.snapshot() == ()


@pytest.mark.parametrize("stage", ("enter", "get", "registry", "projection", "exit"))
def test_blacklist_get_dependency_matrix_is_safe_direct(stage):
    config = _StagedConfig(stage)
    registry = FakeRegistry()
    control = ContentBlacklistControl(config=config, registry=registry)
    failure = RuntimeError(f"blacklist {stage} failed {MARKER}")
    if stage == "registry":
        registry.all_channels = lambda: (_ for _ in ()).throw(failure)
    if stage == "projection":
        control._snapshot_from = lambda _cfg, _channels: (
            _ for _ in ()
        ).throw(failure)

    with pytest.raises(ManagementError) as caught:
        control.get(_management_context())
    _assert_safe_dependency(caught.value)


@pytest.mark.parametrize("stage", ("enter", "get", "registry", "projection"))
def test_blacklist_get_dependency_matrix_is_stable_http(tmp_path, stage):
    app, _runtime, fixture = build_p6_app(tmp_path)
    failure = RuntimeError(f"blacklist HTTP {stage} failed {MARKER}")
    if stage == "enter":
        @contextmanager
        def transaction():
            raise failure
            yield
        fixture.config.serialized_updates = transaction
    elif stage == "get":
        fixture.config.get = lambda: (_ for _ in ()).throw(failure)
    elif stage == "registry":
        fixture.registry.all_channels = lambda: (_ for _ in ()).throw(failure)
    else:
        fixture.controls.blacklist._snapshot_from = lambda _cfg, _channels: (
            _ for _ in ()
        ).throw(failure)

    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(PREFIX + "/content-blacklist", headers=headers)
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert MARKER not in response.text


@pytest.mark.parametrize(
    ("stage", "expected_updates"),
    (
        ("enter", 0),
        ("get", 0),
        ("registry", 0),
        ("update", 0),
        ("final_projection", 1),
        ("exit", 1),
    ),
)
def test_blacklist_management_mutation_dependency_matrix_is_safe_and_audited(
    stage, expected_updates,
):
    config = _StagedConfig(stage)
    registry = FakeRegistry()
    audit = BoundedAuditSink()
    control = ContentBlacklistControl(
        config=config, registry=registry, audit_sink=audit,
    )
    failure = RuntimeError(f"blacklist mutation {stage} failed {MARKER}")
    if stage == "registry":
        registry.all_channels = lambda: (_ for _ in ()).throw(failure)
    if stage == "final_projection":
        original = control._snapshot_from
        calls = 0

        def projection(cfg, channels):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise failure
            return original(cfg, channels)

        control._snapshot_from = projection

    before = copy.deepcopy(config.value)
    with pytest.raises(ManagementError) as caught:
        control.add_default(_management_context(), "blocked-term")
    _assert_safe_dependency(caught.value)
    assert config.updates == expected_updates
    if expected_updates == 0:
        assert config.value == before
    else:
        assert "blocked-term" in config.value["contentBlacklist"]["default"]
    _assert_failed_audit(
        audit, action="content_blacklist.default.add",
    )


_BLACKLIST_TG_CALLS = (
    lambda control: control.telegram_add_default(_telegram_context(), "new-term"),
    lambda control: control.telegram_delete_default(_telegram_context(), "old-term"),
    lambda control: control.add_telegram_channel(
        _telegram_context(), "display/name", "channel-term",
    ),
)


@pytest.mark.parametrize("invoke", _BLACKLIST_TG_CALLS)
def test_blacklist_telegram_commands_preserve_raw_write_failure(invoke):
    class RawConfig:
        def __init__(self) -> None:
            self.raw = RuntimeError(f"telegram blacklist raw {MARKER}")

        def update(self, _mutator):
            raise self.raw

    class NoRegistryRead:
        def all_channels(self):
            raise AssertionError("Telegram command must not read registry")

    config = RawConfig()
    control = ContentBlacklistControl(config=config, registry=NoRegistryRead())
    with pytest.raises(RuntimeError) as caught:
        invoke(control)
    assert caught.value is config.raw


@pytest.mark.parametrize("invoke", _BLACKLIST_TG_CALLS)
def test_blacklist_telegram_commands_have_no_post_write_registry_read(invoke):
    class NoRegistryRead:
        def __init__(self) -> None:
            self.calls = 0

        def all_channels(self):
            self.calls += 1
            raise AssertionError("Telegram command must not read registry")

    config = FakeConfig()
    config.value["contentBlacklist"] = {
        "default": ["old-term"], "byChannel": {},
    }
    registry = NoRegistryRead()
    control = ContentBlacklistControl(config=config, registry=registry)
    invoke(control)
    assert config.updates == 1
    assert registry.calls == 0


@pytest.mark.parametrize(
    ("case", "path"),
    (
        ("settings_config", "/network"),
        ("settings_projection", "/network"),
        ("cache", "/network/dns/cache"),
        ("monitor", "/network/monitor"),
        ("checks", "/network/monitor/checks"),
    ),
)
def test_network_read_gateway_and_projection_failures_are_stable_http(
    tmp_path, case, path,
):
    app, _runtime, fixture = build_p6_app(tmp_path)
    failure = RuntimeError(f"network read {case} failed {MARKER}")
    if case == "settings_config":
        fixture.gateway.config_get = lambda: (
            _ for _ in ()
        ).throw(failure)
    elif case == "settings_projection":
        fixture.controls.network._network = lambda *_args, **_kwargs: (
            _ for _ in ()
        ).throw(failure)
    elif case == "cache":
        fixture.gateway.dns_cache = lambda: (
            _ for _ in ()
        ).throw(failure)
    elif case == "monitor":
        fixture.gateway.monitor_config = lambda: (
            _ for _ in ()
        ).throw(failure)
    else:
        fixture.gateway.checks = lambda: (
            _ for _ in ()
        ).throw(failure)

    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(PREFIX + path, headers=headers)
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert MARKER not in response.text


def _operation_plan_id(runtime, context, operation_id: str) -> str:
    operation = runtime.operations.get(context, operation_id)
    assert operation.status is OperationStatus.SUCCEEDED
    return operation.result["plan"]["id"]


@pytest.mark.parametrize("stage", ("enter", "config", "exit"))
def test_network_test_setup_transaction_failures_are_safe_without_operation(
    tmp_path, stage,
):
    _app, runtime, fixture = build_p6_app(tmp_path)
    context = _management_context()
    failure = RuntimeError(f"network setup {stage} failed {MARKER}")
    if stage == "config":
        fixture.gateway.config_get = lambda: (
            _ for _ in ()
        ).throw(failure)
    else:
        @contextmanager
        def transaction():
            if stage == "enter":
                raise failure
            yield
            if stage == "exit":
                raise failure
        fixture.gateway.serialized_updates = transaction

    before_operations = copy.deepcopy(runtime.operations._items)
    with pytest.raises(ManagementError) as caught:
        fixture.controls.network.start_dns_test(context, ["1.1.1.1"])
    _assert_safe_dependency(caught.value)
    assert runtime.operations._items == before_operations
    _assert_failed_audit(fixture.audit, action="network.dns.test")


@pytest.mark.parametrize(
    ("stage", "action"),
    (
        ("commit_gateway", "network.dns.commit"),
        ("commit_exit", "network.dns.commit"),
        ("sync_enter", "network.dns.sync"),
        ("sync_gateway", "network.dns.sync"),
        ("state_config", "network.socks5.state.update"),
        ("state_gateway", "network.socks5.state.update"),
        ("monitor_enter", "network.monitor.update"),
        ("monitor_gateway", "network.monitor.update"),
        ("monitor_exit", "network.monitor.update"),
    ),
)
def test_network_mutation_transaction_and_gateway_failures_are_safe_and_audited(
    tmp_path, stage, action,
):
    _app, runtime, fixture = build_p6_app(tmp_path)
    context = _management_context()
    control = fixture.controls.network
    failure = RuntimeError(f"network {stage} failed {MARKER}")
    plan_id = None
    if stage.startswith("commit"):
        started = control.start_dns_test(context, ["1.1.1.1"])
        plan_id = _operation_plan_id(runtime, context, started.id)

    if stage == "commit_gateway":
        fixture.gateway.save_dns = lambda _servers: (
            _ for _ in ()
        ).throw(failure)
    elif stage == "commit_exit":
        @contextmanager
        def transaction():
            yield
            raise failure
        fixture.gateway.serialized_updates = transaction
    elif stage == "sync_enter":
        @contextmanager
        def transaction():
            raise failure
            yield
        fixture.gateway.serialized_updates = transaction
    elif stage == "sync_gateway":
        fixture.gateway.sync_system_dns = lambda: (
            _ for _ in ()
        ).throw(failure)
    elif stage == "state_config":
        fixture.gateway.config_get = lambda: (
            _ for _ in ()
        ).throw(failure)
    elif stage == "state_gateway":
        fixture.gateway.set_socks5_enabled = lambda _enabled: (
            _ for _ in ()
        ).throw(failure)
    elif stage == "monitor_enter":
        @contextmanager
        def transaction():
            raise failure
            yield
        fixture.gateway.monitor_transaction = transaction
    elif stage == "monitor_gateway":
        fixture.gateway.update_monitor = lambda _mutator: (
            _ for _ in ()
        ).throw(failure)
    elif stage == "monitor_exit":
        @contextmanager
        def transaction():
            yield
            raise failure
        fixture.gateway.monitor_transaction = transaction

    prior = len([row for row in fixture.audit.snapshot() if row.action == action])
    with pytest.raises(ManagementError) as caught:
        if stage.startswith("commit"):
            control.commit_dns(context, plan_id, force=False)
        elif stage.startswith("sync"):
            control.sync_system_dns(context)
        elif stage.startswith("state"):
            control.update_socks5_state(context, False)
        else:
            control.update_monitor(context, {"dns": True})
    _assert_safe_dependency(caught.value)
    _assert_failed_audit(fixture.audit, action=action, prior=prior)
    new_records = [
        row for row in fixture.audit.snapshot()[prior:]
        if row.action == action
    ]
    assert all(row.result != "succeeded" for row in new_records)


def test_network_gateway_failure_is_stable_and_secret_free_http(tmp_path):
    app, _runtime, fixture = build_p6_app(tmp_path)
    failure = RuntimeError(f"network HTTP sync failed {MARKER}")
    fixture.gateway.sync_system_dns = lambda: (_ for _ in ()).throw(failure)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.post(
            PREFIX + "/network/dns/actions/sync-system", headers=headers,
        )
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert MARKER not in response.text
    _assert_failed_audit(fixture.audit, action="network.dns.sync")


@pytest.mark.parametrize("kind", ("dns", "socks5", "monitor"))
def test_network_worker_terminal_failures_are_stable_operations_and_single_audits(
    tmp_path, kind,
):
    _app, runtime, fixture = build_p6_app(tmp_path)
    context = _management_context()
    failure = RuntimeError(f"network {kind} worker failed {MARKER}")
    control = fixture.controls.network
    if kind == "dns":
        fixture.gateway.test_dns = lambda _servers: (
            _ for _ in ()
        ).throw(failure)
        operation = control.start_dns_test(context, ["1.1.1.1"])
        action = "network.dns.test"
    elif kind == "socks5":
        async def fail_socks5(_url):
            raise failure
        fixture.gateway.test_socks5 = fail_socks5
        operation = control.start_socks5_test(
            context, "socks5://proxy.invalid:1080",
        )
        action = "network.socks5.test"
    else:
        fixture.gateway.format_monitor_result = lambda _item: (
            _ for _ in ()
        ).throw(failure)
        operation = control.run_monitor(context)
        action = "network.monitor.run"

    terminal = runtime.operations.get(context, operation.id)
    assert terminal.status is OperationStatus.FAILED
    assert terminal.result is None
    assert terminal.error is not None
    assert terminal.error.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
    assert terminal.error.message == "DEPENDENCY_UNAVAILABLE"
    assert MARKER not in repr(terminal)
    records = [row for row in fixture.audit.snapshot() if row.action == action]
    assert len(records) == 1
    assert records[0].result == "failed"
    assert MARKER not in repr(records[0])


@pytest.mark.parametrize(
    ("method", "gateway_method", "args", "kwargs"),
    (
        ("telegram_parse_dns", "parse_dns_text", ("1.1.1.1",), {}),
        ("telegram_test_dns", "test_dns", (_telegram_context(), ["1.1.1.1"]), {}),
        ("telegram_normalize_socks5", "normalize_socks5", ("proxy:1080",), {}),
        ("telegram_save_dns", "save_dns", (_telegram_context(), ["1.1.1.1"], {"ok": True}), {"force": False}),
        ("telegram_save_socks5", "save_socks5", (_telegram_context(), "socks5://proxy:1080", {"ok": True}), {"force": False}),
        ("telegram_sync_dns", "sync_system_dns", (_telegram_context(),), {}),
        ("telegram_clear_dns_cache", "clear_dns_cache", (_telegram_context(),), {}),
        ("telegram_set_socks5_enabled", "set_socks5_enabled", (_telegram_context(), False), {}),
        ("telegram_update_monitor", "update_monitor", (_telegram_context(), lambda _cfg: None), {}),
        ("telegram_set_monitor_channel", "set_monitor_channel", (_telegram_context(), "api:example", True), {}),
    ),
)
def test_network_synchronous_telegram_compatibility_preserves_raw_exceptions(
    tmp_path, method, gateway_method, args, kwargs,
):
    _app, _runtime, fixture = build_p6_app(tmp_path)
    raw = RuntimeError(f"telegram network raw {MARKER}")
    setattr(
        fixture.gateway, gateway_method,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(raw),
    )
    with pytest.raises(RuntimeError) as caught:
        getattr(fixture.controls.network, method)(*args, **kwargs)
    assert caught.value is raw


def test_network_async_telegram_compatibility_preserves_raw_exceptions(tmp_path):
    _app, _runtime, fixture = build_p6_app(tmp_path)
    raw = RuntimeError(f"telegram async network raw {MARKER}")

    async def fail(*_args, **_kwargs):
        raise raw

    fixture.gateway.test_socks5 = fail
    with pytest.raises(RuntimeError) as socks:
        asyncio.run(
            fixture.controls.network.telegram_test_socks5(
                _telegram_context(), "socks5://proxy:1080",
            ),
        )
    assert socks.value is raw

    fixture.gateway.run_monitor = fail
    with pytest.raises(RuntimeError) as monitor:
        asyncio.run(
            fixture.controls.network.telegram_run_monitor(_telegram_context()),
        )
    assert monitor.value is raw

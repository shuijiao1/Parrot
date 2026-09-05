from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from src.management_auth import AuthMethod
from src.management_auth.principal import ManagementPrincipal
from src.management_control import ManagementContext, OperationRegistry, OperationStore
from src.management_control.auxiliary.updates import UpdateControl
from src.management_control.operations import OperationStatus
from src.tests.management_auxiliary_support import (
    FakeConfig,
    FakeUpdates,
    bearer,
    build_auxiliary_app,
    create_session,
)


BASE = "/api/management/v1"
_START = datetime(2026, 1, 2, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self) -> None:
        self.now = _START
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self.now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.now += timedelta(seconds=seconds)


class SlowStageUpdates(FakeUpdates):
    def __init__(self, config: FakeConfig, clock: FakeClock) -> None:
        super().__init__(config)
        self._clock = clock

    def stage(self, version, *, chat_id=None, notify_msg_id=None):
        self._clock.advance(601)
        return super().stage(version, chat_id=chat_id, notify_msg_id=notify_msg_id)


class RetryActivationUpdates(FakeUpdates):
    def activate(self):
        self.activate_calls += 1
        if self.activate_calls == 1:
            self.update_state["message"] = "state snapshot guard rejected restart"
            return False, "private guard detail"
        self.update_state["stage"] = "success"
        return True, "accepted"


class CloseDuringRearmUpdates(FakeUpdates):
    """Pause the post-failure state read so owner close wins the terminal race."""

    def __init__(self, config: FakeConfig) -> None:
        super().__init__(config)
        self.rearm_state_entered = threading.Event()
        self.release_rearm_state = threading.Event()
        self._blocked_once = False

    def activate(self):
        self.activate_calls += 1
        self.update_state["message"] = "state snapshot guard rejected restart"
        return False, "private guard detail"

    def state(self):
        if self.activate_calls and not self._blocked_once:
            self._blocked_once = True
            self.rearm_state_entered.set()
            assert self.release_rearm_state.wait(timeout=3)
        return super().state()


class NoExitUpdates(FakeUpdates):
    def __init__(self, config: FakeConfig) -> None:
        super().__init__(config)
        self.activated = threading.Event()

    def activate(self):
        self.activate_calls += 1
        self.update_state["stage"] = "restarting"
        self.activated.set()
        return True, "accepted"

    def activation_is_terminal(self):
        return False


class BlockingStageUpdates(FakeUpdates):
    def __init__(self, config: FakeConfig) -> None:
        super().__init__(config)
        self.api_entered = threading.Event()
        self.allow_api_finish = threading.Event()
        self.api_callback_preserved = False
        self.callbacks = []

    def set_progress(self, callback):
        if callback is not None:
            self.callbacks.append(callback)
        self.progress = callback

    def stage(self, version, *, chat_id=None, notify_msg_id=None):
        self.stage_calls.append(version)
        if len(self.stage_calls) > 1:
            return False, "already staged"
        api_callback = self.progress
        assert api_callback is not None
        api_callback("backing_up", "backup")
        self.api_entered.set()
        assert self.allow_api_finish.wait(timeout=5)
        self.api_callback_preserved = self.progress is api_callback
        api_callback("pulling", "pull")
        self.update_state = {
            "stage": "staged",
            "mode": "docker",
            "target_tag": version,
            "message": "ready",
        }
        api_callback("staged", "ready")
        return True, "ready"


def _config() -> FakeConfig:
    return FakeConfig({"updateChecker": {"ignoredVersions": []}})


def _context(idempotency_key: str, *, transport: str = "api") -> ManagementContext:
    principal = ManagementPrincipal.administrator(
        subject_id=f"{transport}:administrator",
        auth_method=(
            AuthMethod.MANAGEMENT_KEY if transport == "api" else AuthMethod.TELEGRAM_ADMIN
        ),
        issued_at=_START,
        session_id="session-update-owner" if transport == "api" else None,
    )
    return ManagementContext(
        request_id=f"request-{idempotency_key}",
        actor=principal,
        idempotency_key=idempotency_key,
    )


def _bound_control(gateway, clock: FakeClock, **kwargs):
    store = OperationStore(clock=clock, max_workers=3, shutdown_timeout_seconds=0.1)
    registry = OperationRegistry(store)
    control = UpdateControl(
        config_gateway=gateway.config,
        update_gateway=gateway,
        clock=clock,
        **kwargs,
    )
    control.bind_operations(store, registry)
    return control, store


def _terminal(store: OperationStore, context: ManagementContext, operation_id: str):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        operation = store.get(context, operation_id)
        if operation.status in {
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        }:
            return operation
        time.sleep(0.005)
    raise AssertionError(f"operation {operation_id} did not terminate")


def _stage(control: UpdateControl, store: OperationStore):
    context = _context("stage")
    submission = control.stage_update(context, "0.32.0")
    terminal = _terminal(store, context, submission.operation.id)
    assert terminal.status is OperationStatus.SUCCEEDED
    return context, submission.activation_plan_token, terminal.result


def test_slow_stage_gets_full_ttl_only_after_authoritative_staged_state():
    clock = FakeClock()
    gateway = SlowStageUpdates(_config(), clock)
    control, store = _bound_control(gateway, clock)
    try:
        _, token, plan = _stage(control, store)
        assert token is not None
        assert plan["expiresAt"] == "2026-01-02T00:20:01Z"
        assert control._plans[control._active_plan_digest].expires_at - clock() == timedelta(seconds=600)

        activate_context = _context("activate-after-slow-stage")
        activation = control.activate_staged(
            activate_context,
            plan_token=token,
            expected_revision=plan["expectedRevision"],
        )
        assert _terminal(store, activate_context, activation.id).status is OperationStatus.SUCCEEDED
        assert gateway.activate_calls == 1
    finally:
        store.close()


def test_synchronous_restart_failure_rearms_only_same_staged_version_for_retry():
    clock = FakeClock()
    gateway = RetryActivationUpdates(_config())
    control, store = _bound_control(gateway, clock)
    try:
        _, token, plan = _stage(control, store)
        assert token is not None
        original_revision = plan["expectedRevision"]

        first_context = _context("activate-first")
        first = control.activate_staged(
            first_context,
            plan_token=token,
            expected_revision=original_revision,
        )
        failed = _terminal(store, first_context, first.id)
        assert failed.status is OperationStatus.FAILED
        assert failed.error is not None and failed.error.retryable is True
        digest = control._active_plan_digest
        assert digest is not None
        assert control._plans[digest].consumed is False
        assert control._plans[digest].revision != original_revision

        second_context = _context("activate-retry")
        second = control.activate_staged(
            second_context,
            plan_token=token,
            # The response revision remains usable only with the rearmed plan.
            expected_revision=original_revision,
        )
        assert _terminal(store, second_context, second.id).status is OperationStatus.SUCCEEDED
        assert gateway.activate_calls == 2
        assert control._plans[digest].consumed is True
        assert control._active_plan_digest is None
    finally:
        store.close()


def test_owner_close_during_failed_activation_rearm_retires_plan():
    clock = FakeClock()
    gateway = CloseDuringRearmUpdates(_config())
    control, store = _bound_control(gateway, clock)
    _, token, plan = _stage(control, store)
    digest = control._active_plan_digest
    assert token is not None and digest is not None

    activate_context = _context("activate-close-during-rearm")
    activation = control.activate_staged(
        activate_context,
        plan_token=token,
        expected_revision=plan["expectedRevision"],
    )
    assert gateway.rearm_state_entered.wait(timeout=2)

    assert store.close(timeout_seconds=0) == 1
    interrupted = store.get(activate_context, activation.id)
    assert interrupted.status is OperationStatus.FAILED
    gateway.release_rearm_state.set()

    deadline = time.monotonic() + 2
    while activation.id in store._futures and time.monotonic() < deadline:
        time.sleep(0.005)
    assert activation.id not in store._futures
    assert (control._active_plan_digest, control._plans[digest].consumed) == (None, True)


def test_restart_acceptance_without_process_exit_has_bounded_failed_terminal():
    clock = FakeClock()
    gateway = NoExitUpdates(_config())
    control, store = _bound_control(
        gateway,
        clock,
        activation_timeout_seconds=5,
        activation_poll_interval_seconds=1,
        activation_wait=clock.advance,
    )
    try:
        _, token, plan = _stage(control, store)
        activate_context = _context("activate-no-exit")
        activation = control.activate_staged(
            activate_context,
            plan_token=token,
            expected_revision=plan["expectedRevision"],
        )
        terminal = _terminal(store, activate_context, activation.id)
        assert terminal.status is OperationStatus.FAILED
        assert terminal.error is not None
        assert terminal.error.code.value == "UPSTREAM_TIMEOUT"
        assert terminal.error.retryable is False
        assert terminal.result is None
        assert gateway.activate_calls == 1
        assert control._active_plan_digest is None
    finally:
        store.close()


def test_activation_monitor_converges_when_operation_owner_closes():
    clock = FakeClock()
    gateway = NoExitUpdates(_config())
    wait_entered = threading.Event()
    release_wait = threading.Event()

    def blocking_wait(_seconds: float) -> None:
        wait_entered.set()
        release_wait.wait(timeout=2)

    control, store = _bound_control(
        gateway,
        clock,
        activation_timeout_seconds=1000,
        activation_poll_interval_seconds=1,
        activation_wait=blocking_wait,
    )
    _, token, plan = _stage(control, store)
    activate_context = _context("activate-before-close")
    activation = control.activate_staged(
        activate_context,
        plan_token=token,
        expected_revision=plan["expectedRevision"],
    )
    assert gateway.activated.wait(timeout=2)
    assert wait_entered.wait(timeout=2)

    started = time.monotonic()
    interrupted = store.close(timeout_seconds=0.02)
    elapsed = time.monotonic() - started
    try:
        assert interrupted == 1
        assert elapsed < 0.5
        terminal = store.get(activate_context, activation.id)
        assert terminal.status is OperationStatus.FAILED
        assert terminal.error is not None
        assert terminal.error.code.value == "DEPENDENCY_UNAVAILABLE"
    finally:
        release_wait.set()
    deadline = time.monotonic() + 2
    while activation.id in store._futures and time.monotonic() < deadline:
        time.sleep(0.005)
    assert activation.id not in store._futures


def test_api_and_telegram_stage_share_callback_lock_without_deadlock():
    clock = FakeClock()
    gateway = BlockingStageUpdates(_config())
    control, store = _bound_control(gateway, clock)
    api_context = _context("api-stage")
    tg_context = _context("unused-for-tg", transport="telegram")
    tg_done = threading.Event()
    tg_result = {}
    try:
        submission = control.stage_update(api_context, "0.32.0")
        assert gateway.api_entered.wait(timeout=2)

        def run_tg_stage() -> None:
            tg_result["value"] = control.stage_direct(
                tg_context,
                "0.33.0",
                progress=lambda _stage, _message: None,
                chat_id=42,
                notify_msg_id=100,
            )
            tg_done.set()

        thread = threading.Thread(target=run_tg_stage, name="s7-tg-stage")
        thread.start()
        assert not tg_done.wait(timeout=0.05)
        gateway.allow_api_finish.set()
        terminal = _terminal(store, api_context, submission.operation.id)
        thread.join(timeout=2)

        assert not thread.is_alive()
        assert tg_done.is_set()
        assert terminal.status is OperationStatus.SUCCEEDED
        assert terminal.progress is not None
        assert (terminal.progress.current, terminal.progress.total) == (3, 3)
        assert terminal.progress.message_code == "UPDATE_STAGED"
        assert gateway.api_callback_preserved is True
        assert gateway.progress is None
        assert len(gateway.callbacks) == 2
        assert gateway.callbacks[0] is not gateway.callbacks[1]
        assert tg_result["value"] == (False, "already staged")
    finally:
        gateway.allow_api_finish.set()
        store.close()


def test_failure_log_api_masks_only_known_fields_and_url_userinfo(tmp_path):
    app, runtime, fixture = build_auxiliary_app(tmp_path)
    raw = (
        "api_token=field-secret\n"
        '{"apiKey":"json-secret","message":"token=ordinary"}\n'
        "fetch https://alice:hunter2@example.invalid/repo failed\n"
        "ssh://deploy@example.invalid/project token=ordinary\n"
        "health failed with secret prose unchanged"
    )
    fixture.update_gateway.failure_log = lambda: raw
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        response = client.get(BASE + "/updates/failure-log", headers=headers)
        assert response.status_code == 200
        assert response.json()["data"]["content"] == (
            "api_token=***\n"
            '{"apiKey":"***","message":"token=ordinary"}\n'
            "fetch https://***:***@example.invalid/repo failed\n"
            "ssh://***@example.invalid/project token=ordinary\n"
            "health failed with secret prose unchanged"
        )

        tg_session = runtime.sessions.issue_for_principal(
            subject_id="telegram:update-admin",
            auth_method=AuthMethod.TELEGRAM_ADMIN,
            roles=(),
            capabilities=tuple(ManagementPrincipal.administrator(
                subject_id="capability-source",
                auth_method=AuthMethod.TELEGRAM_ADMIN,
                issued_at=_START,
            ).capabilities),
        )
        tg_context = ManagementContext(request_id="tg-raw-log", actor=tg_session.principal)
        assert fixture.controls.updates.failure_log_raw(tg_context) == raw


def test_failure_log_api_masks_url_userinfo_with_original_uppercase_scheme(tmp_path):
    app, _runtime, fixture = build_auxiliary_app(tmp_path)
    raw = (
        "fetch HtTp://alice:hunter2@example.invalid/repo failed\n"
        "fetch HTTPS://bob@example.invalid/repo failed\n"
        "fetch SSH://deploy:key@example.invalid/project failed"
    )
    fixture.update_gateway.failure_log = lambda: raw

    with TestClient(app) as client:
        response = client.get(
            BASE + "/updates/failure-log",
            headers=bearer(create_session(client)),
        )

    assert response.status_code == 200
    assert response.json()["data"]["content"] == (
        "fetch HtTp://***:***@example.invalid/repo failed\n"
        "fetch HTTPS://***@example.invalid/repo failed\n"
        "fetch SSH://***:***@example.invalid/project failed"
    )

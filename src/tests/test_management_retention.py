from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.management_api.dependencies import ManagementRuntime
from src.management_api.routers._observability import controls as resolve_controls
from src.management_auth import AuthMethod, ManagementPrincipal
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode, OperationStore
from src.management_control.observability import RetentionControl, RetentionMode
from src.tests.management_observability_support import build_client


class Clock:
    def __init__(self, value=1_700_000_000.0):
        self.value = value

    def __call__(self):
        return self.value


class FakeConfig:
    def __init__(self):
        self.value = {
            "logRetention": {"mode": "forever", "days": None},
            "logStoreBodies": True,
        }
        self.updates = 0

    def get(self):
        return self.value

    def update(self, mutate):
        self.updates += 1
        mutate(self.value)
        return self.value


class FakeLogDb:
    def __init__(self):
        self.apply_calls = []
        self.authority_calls = []
        self.apply_result = None

    def retention_policy(self, cfg=None):
        value = cfg or self.config.value
        return dict(value.get("logRetention") or {"mode": "forever", "days": None})

    def recent_logs_count(self):
        return 12

    def retention_cleanup_busy(self):
        return False

    def set_retention_forever(self):
        self.authority_calls.append(("forever", None))
        self.config.update(lambda cfg: cfg.__setitem__(
            "logRetention", {"mode": "forever", "days": None},
        ))
        return {"ok": True}

    def extend_retention_days(self, days):
        self.authority_calls.append(("extend", days))
        self.config.update(lambda cfg: cfg.__setitem__(
            "logRetention", {"mode": "days", "days": days},
        ))
        return {"ok": True}

    def plan_retention(self, days):
        return {
            "days": days, "cutoff": 1_699_000_000, "reference_ts": 1_700_000_000,
            "created_at": 1_700_000_000,
            "base_policy": {"mode": "forever", "days": None},
            "items": [{"month": "2023-01", "expired_requests": 4, "bundle_bytes": 100}],
            "errors": [], "scanned_months": 2, "scanned_bytes": 300,
            "scanned_requests": 12, "preflight": {"ok": True}, "signature": "signature",
        }

    def apply_retention_plan(self, plan, *, activate_policy, progress):
        self.apply_calls.append((plan, activate_policy))
        progress({"phase": "delete", "index": 1})
        if isinstance(self.apply_result, BaseException):
            raise self.apply_result
        if self.apply_result is not None:
            return self.apply_result
        return {
            "ok": True, "deleted_requests": 4, "processed_files": 1,
            "logical_bytes_removed": 100, "actual_free_bytes": 80,
            "days": plan["days"], "config_saved": True,
        }


def make_context(*, request="retention", idempotency=None, subject="actor", session="session"):
    return ManagementContext(
        request_id=request, idempotency_key=idempotency,
        actor=ManagementPrincipal.administrator(
            subject_id=subject, auth_method=AuthMethod.MANAGEMENT_KEY, session_id=session,
        ),
    )


def test_production_runtime_owns_observability_audit_for_api_mutations(tmp_path):
    client, runtime, _, auth = build_client(tmp_path, inject_controls=False)
    bound = resolve_controls(SimpleNamespace(app=client.app))
    assert bound.stats.audit_sink is runtime.audit_sink
    assert bound.retention.audit_sink is runtime.audit_sink

    stats_config = FakeConfig()
    stats_config.value["telegram"] = {}
    bound.stats.config = stats_config
    retention_config = FakeConfig()
    db = FakeLogDb()
    db.config = retention_config
    bound.retention.config = retention_config
    bound.retention.log_db = db
    bound.retention._start_worker = lambda worker: worker()

    stats = client.patch(
        "/api/management/v1/preferences/telegram/stats",
        json={"byChannel": False}, headers=auth,
    )
    settings = client.patch(
        "/api/management/v1/logs/retention",
        json={"logStoreBodies": False}, headers=auth,
    )
    plan_response = client.post(
        "/api/management/v1/logs/retention/plans", json={"days": 30}, headers=auth,
    )
    assert stats.status_code == settings.status_code == 200
    assert plan_response.status_code == 201, plan_response.text
    plan = plan_response.json()["data"]
    committed = client.post(
        f"/api/management/v1/logs/retention/plans/{plan['id']}/commit",
        headers={**auth, "If-Match": plan["revision"]},
    )
    second_plan = client.post(
        "/api/management/v1/logs/retention/plans", json={"days": 60}, headers=auth,
    ).json()["data"]
    cancelled = client.delete(
        f"/api/management/v1/logs/retention/plans/{second_plan['id']}", headers=auth,
    )
    assert committed.status_code == 202, committed.text
    assert cancelled.status_code == 204

    records = runtime.state_store.audit_snapshot()
    actions = {record["action"] for record in records}
    assert {
        "stats.preferences.update", "retention.settings.update",
        "retention.plan.create", "retention.plan.commit", "retention.plan.cancel",
    } <= actions
    mutations = [
        record for record in records
        if record["action"].startswith(("stats.", "retention."))
    ]
    assert mutations
    assert all(record["actor"] == "administrator" for record in mutations)
    assert all(record["request_id"] == "request-p4-test" for record in mutations)
    assert all(record["target"] and record["result"] for record in mutations)
    serialized = json.dumps(mutations)
    assert "pmk_" not in serialized
    assert auth["Authorization"].split(" ", 1)[1] not in serialized


def test_retention_api_happy_202_control_once_validation_and_conflicts(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    cases = [
        ("GET", "/api/management/v1/logs/retention", None, {}, 200, controls.retention.settings),
        ("PATCH", "/api/management/v1/logs/retention", {"logStoreBodies": False}, {}, 200, controls.retention.update_settings),
        ("POST", "/api/management/v1/logs/retention/plans", {"days": 30}, {}, 201, controls.retention.create_plan),
        ("POST", "/api/management/v1/logs/retention/plans/plan_example/commit", None, {"If-Match": "rev_plan"}, 202, controls.retention.commit_plan),
        ("DELETE", "/api/management/v1/logs/retention/plans/plan_example", None, {}, 204, controls.retention.cancel_plan),
    ]
    for method, path, body, extra, expected, mocked in cases:
        response = client.request(method, path, json=body, headers={**auth, **extra})
        assert response.status_code == expected, response.text
        mocked.assert_called_once()
        assert mocked.call_args.args[0].actor.subject_id == "administrator"
    bad = client.post(
        "/api/management/v1/logs/retention/plans", json={"days": 0}, headers=auth,
    )
    assert bad.status_code == 422
    assert bad.json()["error"]["fields"][0]["path"] == "days"
    missing_revision = client.post(
        "/api/management/v1/logs/retention/plans/plan_example/commit", headers=auth,
    )
    assert missing_revision.status_code == 422
    assert missing_revision.json()["error"]["fields"][0]["path"] == "If-Match"
    controls.retention.update_settings.side_effect = ManagementError(ManagementErrorCode.REVISION_CONFLICT)
    stale = client.patch(
        "/api/management/v1/logs/retention", json={"mode": "forever"},
        headers={**auth, "If-Match": "stale"},
    )
    assert stale.status_code == 409


def test_retention_control_policy_only_prepare_commit_terminal_replay_and_actor_binding():
    clock = Clock()
    config = FakeConfig()
    db = FakeLogDb()
    db.config = config
    control = RetentionControl(
        log_db=db, config=config, now=clock, start_worker=lambda worker: worker(),
    )
    operations = OperationStore(
        clock=lambda: datetime.fromtimestamp(clock(), tz=timezone.utc),
    )
    ctx = make_context(idempotency="same-key")
    config.value["logRetention"] = {"mode": "days", "days": 30}

    before = control.settings(ctx)
    updated = control.update_settings(
        ctx, mode=RetentionMode.DAYS, days=90, log_store_bodies=False,
        expected_revision=before["revision"],
    )
    assert updated["days"] == 90 and updated["logStoreBodies"] is False
    assert db.authority_calls == [("extend", 90)]
    assert db.apply_calls == []
    with pytest.raises(ManagementError) as stale:
        control.update_settings(
            ctx, mode=RetentionMode.FOREVER, days=None, log_store_bodies=None,
            expected_revision=before["revision"],
        )
    assert stale.value.code is ManagementErrorCode.REVISION_CONFLICT

    plan = control.create_plan(ctx, days=30)
    assert plan["affectedRows"] == 4 and plan["state"] == "prepared"
    assert control.create_plan(ctx, days=30)["id"] == plan["id"]
    with pytest.raises(ManagementError) as changed_payload:
        control.create_plan(ctx, days=31)
    assert changed_payload.value.code is ManagementErrorCode.RESOURCE_CONFLICT
    operation = control.commit_plan(
        ctx, plan["id"], expected_revision=plan["revision"], operations=operations,
    )
    terminal = operations.get(ctx, operation.id)
    assert terminal.status.value == "succeeded"
    assert terminal.result["deletedRows"] == 4
    assert db.apply_calls[0][1] is True
    replay = control.commit_plan(
        ctx, plan["id"], expected_revision=plan["revision"], operations=operations,
    )
    assert replay.id == operation.id
    with pytest.raises(ManagementError) as duplicate:
        control.commit_plan(
            make_context(idempotency="other-key"), plan["id"],
            expected_revision=plan["revision"], operations=operations,
        )
    assert duplicate.value.code is ManagementErrorCode.STATE_CONFLICT

    second = control.create_plan(make_context(idempotency="second"), days=60)
    with pytest.raises(ManagementError) as wrong_actor:
        control.cancel_plan(make_context(idempotency="x", subject="other", session="other"), second["id"])
    assert wrong_actor.value.code is ManagementErrorCode.RESOURCE_NOT_FOUND
    control.cancel_plan(make_context(idempotency="x"), second["id"])
    with pytest.raises(ManagementError) as repeated_cancel:
        control.cancel_plan(make_context(idempotency="x"), second["id"])
    assert repeated_cancel.value.code is ManagementErrorCode.STATE_CONFLICT


def test_retention_dangerous_transitions_are_confirmation_only_and_atomic():
    for policy, target_mode, target_days, field in (
        ({"mode": "forever", "days": None}, RetentionMode.DAYS, 30, "mode"),
        ({"mode": "days", "days": 90}, RetentionMode.DAYS, 30, "days"),
    ):
        config = FakeConfig()
        config.value["logRetention"] = dict(policy)
        db = FakeLogDb()
        db.config = config
        control = RetentionControl(log_db=db, config=config)
        before = control.settings(make_context())

        with pytest.raises(ManagementError) as confirmation:
            control.update_settings(
                make_context(), mode=target_mode, days=target_days,
                log_store_bodies=False, expected_revision=before["revision"],
            )

        assert confirmation.value.code is ManagementErrorCode.CONFIRMATION_REQUIRED
        assert confirmation.value.fields[0].path == field
        assert config.value["logRetention"] == policy
        assert config.value["logStoreBodies"] is True
        assert config.updates == 0
        assert db.authority_calls == []
        assert db.apply_calls == []


def test_retention_safe_policy_changes_use_authoritative_apis_and_validate_patch():
    config = FakeConfig()
    config.value["logRetention"] = {"mode": "days", "days": 30}
    db = FakeLogDb()
    db.config = config
    control = RetentionControl(log_db=db, config=config)
    ctx = make_context()

    current = control.settings(ctx)
    extended = control.update_settings(
        ctx, mode=RetentionMode.DAYS, days=60, log_store_bodies=None,
        expected_revision=current["revision"],
    )
    assert extended["days"] == 60
    assert db.authority_calls == [("extend", 60)]

    forever = control.update_settings(
        ctx, mode=RetentionMode.FOREVER, days=None, log_store_bodies=None,
        expected_revision=extended["revision"],
    )
    assert forever["mode"] == "forever" and forever["days"] is None
    assert db.authority_calls[-1] == ("forever", None)

    updates = config.updates
    same = control.update_settings(
        ctx, mode=RetentionMode.FOREVER, days=None, log_store_bodies=None,
        expected_revision=forever["revision"],
    )
    assert same["revision"] == forever["revision"]
    assert config.updates == updates

    config.value["logRetention"] = {"mode": "days", "days": 30}
    original_extend = db.extend_retention_days
    db.extend_retention_days = lambda _days: (_ for _ in ()).throw(RuntimeError("db unavailable"))
    with pytest.raises(ManagementError) as unavailable:
        control.update_settings(
            ctx, mode=RetentionMode.DAYS, days=60, log_store_bodies=None,
            expected_revision=None,
        )
    assert unavailable.value.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
    assert unavailable.value.retryable is True
    db.extend_retention_days = original_extend
    config.value["logRetention"] = {"mode": "forever", "days": None}

    for kwargs, path in (
        ({"mode": None, "days": None, "log_store_bodies": None}, "body"),
        ({"mode": RetentionMode.FOREVER, "days": 10, "log_store_bodies": None}, "days"),
        ({"mode": None, "days": 10, "log_store_bodies": None}, "days"),
    ):
        with pytest.raises(ManagementError) as invalid:
            control.update_settings(ctx, expected_revision=None, **kwargs)
        assert invalid.value.code is ManagementErrorCode.VALIDATION_FAILED
        assert invalid.value.fields[0].path == path


def test_retention_operation_failure_is_terminal_with_stable_code():
    clock = Clock()
    config = FakeConfig()
    db = FakeLogDb()
    db.config = config
    db.apply_result = {"ok": False, "reason": "backend detail must not become a code"}
    control = RetentionControl(
        log_db=db, config=config, now=clock, start_worker=lambda worker: worker(),
    )
    operations = OperationStore(
        clock=lambda: datetime.fromtimestamp(clock(), tz=timezone.utc),
    )
    ctx = make_context(idempotency="failed-operation")
    plan = control.create_plan(ctx, days=30)
    operation = control.commit_plan(
        ctx, plan["id"], expected_revision=plan["revision"], operations=operations,
    )

    terminal = operations.get(ctx, operation.id)
    assert terminal.status.value == "failed"
    assert terminal.finished_at is not None
    assert terminal.error is not None
    assert terminal.error.code is ManagementErrorCode.STATE_CONFLICT
    assert terminal.result is None


def test_retention_expired_plan_fails_without_apply():
    clock = Clock()
    config = FakeConfig()
    db = FakeLogDb()
    db.config = config
    control = RetentionControl(log_db=db, config=config, now=clock, ttl_seconds=1)
    ctx = make_context(idempotency="expiring")
    plan = control.create_plan(ctx, days=30)
    clock.value += 2
    with pytest.raises(ManagementError) as expired:
        control.cancel_plan(ctx, plan["id"])
    assert expired.value.code is ManagementErrorCode.STATE_CONFLICT
    assert db.apply_calls == []


def test_runtime_lazy_binding_is_singleton_under_concurrent_first_requests(tmp_path):
    client, runtime, _, _ = build_client(tmp_path, inject_controls=False)
    barrier = threading.Barrier(2)

    class RacingState:
        def __init__(self, bound_runtime: ManagementRuntime):
            self.management_runtime = bound_runtime
            self._seen_threads = set()
            self._seen_lock = threading.Lock()

        def __getattr__(self, name):
            if name == "management_observability_controls":
                ident = threading.get_ident()
                with self._seen_lock:
                    first_access = ident not in self._seen_threads
                    self._seen_threads.add(ident)
                if first_access:
                    barrier.wait(timeout=5)
            raise AttributeError(name)

    request = SimpleNamespace(app=SimpleNamespace(state=RacingState(runtime)))
    resolved = []
    failures = []

    def bind():
        try:
            resolved.append(resolve_controls(request))
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    threads = [threading.Thread(target=bind) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not failures
    assert all(not thread.is_alive() for thread in threads)
    assert len(resolved) == 2
    assert resolved[0] is resolved[1]
    assert request.app.state.management_observability_controls is resolved[0]
    assert request.app.state.management_observability_controls_runtime is runtime
    client.close()


def test_retention_concurrent_equal_create_idempotency_converges_to_one_plan():
    barrier = threading.Barrier(2)

    class BarrierLogDb(FakeLogDb):
        def __init__(self):
            super().__init__()
            self.scan_calls = []
            self.scan_lock = threading.Lock()

        def plan_retention(self, days):
            with self.scan_lock:
                self.scan_calls.append(days)
            barrier.wait(timeout=5)
            return super().plan_retention(days)

    config = FakeConfig()
    db = BarrierLogDb()
    db.config = config
    control = RetentionControl(log_db=db, config=config)
    ctx = make_context(idempotency="concurrent-equal")
    results = []
    failures = []

    def create():
        try:
            results.append(control.create_plan(ctx, days=30))
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    threads = [threading.Thread(target=create) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not failures
    assert all(not thread.is_alive() for thread in threads)
    assert db.scan_calls == [30, 30]
    assert len({result["id"] for result in results}) == 1
    assert len(control._plans) == 1


def test_retention_concurrent_different_create_payload_conflicts_without_second_plan():
    barrier = threading.Barrier(2)

    class BarrierLogDb(FakeLogDb):
        def plan_retention(self, days):
            barrier.wait(timeout=5)
            return super().plan_retention(days)

    config = FakeConfig()
    db = BarrierLogDb()
    db.config = config
    control = RetentionControl(log_db=db, config=config)
    ctx = make_context(idempotency="concurrent-different")
    results = []
    failures = []

    def create(days):
        try:
            results.append(control.create_plan(ctx, days=days))
        except ManagementError as exc:
            failures.append(exc)

    threads = [
        threading.Thread(target=create, args=(30,)),
        threading.Thread(target=create, args=(60,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 1
    assert len(failures) == 1
    assert failures[0].code is ManagementErrorCode.RESOURCE_CONFLICT
    assert len(control._plans) == 1

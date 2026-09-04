from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.management_auth import AuthMethod, Capability, ManagementPrincipal, authorize
from src.management_control import (
    BoundedAuditSink,
    ManagementContext,
    ManagementError,
    ManagementErrorCode,
    OperationRegistry,
    OperationStatus,
    OperationStore,
)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def principal(
    subject: str = "administrator",
    session: str | None = "session-a",
    capabilities: tuple[Capability, ...] | None = None,
) -> ManagementPrincipal:
    if capabilities is None:
        return ManagementPrincipal.administrator(
            subject_id=subject,
            auth_method=AuthMethod.MANAGEMENT_KEY,
            issued_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            session_id=session,
        )
    return ManagementPrincipal.with_capabilities(
        subject_id=subject,
        auth_method=AuthMethod.MANAGEMENT_KEY,
        capabilities=capabilities,
        issued_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        session_id=session,
    )


def context(**kwargs) -> ManagementContext:
    return ManagementContext(request_id="req-test", actor=principal(**kwargs))


def test_principal_policy_and_context_are_transport_neutral():
    actor = principal()
    authorize(actor, Capability.DESTRUCTIVE)
    assert actor.auth_method is AuthMethod.MANAGEMENT_KEY
    assert actor.roles
    assert context().idempotency_key is None

    restricted = principal(capabilities=(Capability.READ,))
    with pytest.raises(PermissionError):
        authorize(restricted, Capability.WRITE)


def test_management_error_has_stable_fields_and_rejects_unknown_codes():
    error = ManagementError(
        ManagementErrorCode.RATE_LIMITED,
        retryable=True,
        operation_id="op_example",
    )
    assert error.code is ManagementErrorCode.RATE_LIMITED
    assert error.retryable is True
    assert error.operation_id == "op_example"
    with pytest.raises(ValueError):
        ManagementError("NOT_A_STABLE_CODE")


def test_operation_lifecycle_visibility_cancellation_audit_and_secret_redaction():
    clock = Clock()
    audit = BoundedAuditSink(max_records=10)
    store = OperationStore(max_operations=4, clock=clock, audit_sink=audit)
    owner = context()

    operation = store.create(owner, kind="test.refresh", cancellable=True)
    assert operation.status is OperationStatus.QUEUED
    clock.advance(1)
    assert store.mark_running(operation.id).status is OperationStatus.RUNNING
    progress = store.update_progress(
        operation.id, current=1, total=2, message_code="TEST_HALF",
    )
    assert progress.progress and progress.progress.current == 1

    completed = store.succeed(
        operation.id,
        {
            "count": 2,
            "key": "public-check-id",
            "message": "Bearer support is enabled",
            "managementKey": "fake-management-secret",
            "nested": {"exchange_secret": "fake-exchange-secret"},
        },
    )
    assert completed.status is OperationStatus.SUCCEEDED
    assert completed.result == {
        "count": 2,
        "key": "public-check-id",
        "message": "Bearer support is enabled",
        "managementKey": "[REDACTED]",
        "nested": {"exchange_secret": "[REDACTED]"},
    }
    assert "fake-management-secret" not in repr(completed)
    assert "fake-exchange-secret" not in repr(completed)

    other_session = context(session="session-b")
    with pytest.raises(ManagementError) as hidden:
        store.get(other_session, operation.id)
    assert hidden.value.code is ManagementErrorCode.OPERATION_NOT_FOUND

    cancellable = store.create(owner, kind="test.cancel", cancellable=True)
    store.cancel(owner, cancellable.id)
    assert store.get(owner, cancellable.id).status is OperationStatus.CANCELLED
    assert [(r.action, r.result) for r in audit.snapshot()] == [
        ("operation.create", "queued"),
        ("operation.create", "queued"),
        ("operation.cancel", "cancelled"),
    ]
    assert all(r.actor == "administrator" and r.request_id == "req-test" for r in audit.snapshot())


def test_operation_capability_and_capacity_are_enforced_in_control():
    store = OperationStore(max_operations=1)
    reader = context(capabilities=(Capability.READ,))
    with pytest.raises(ManagementError) as denied:
        store.create(reader, kind="test.write", cancellable=True)
    assert denied.value.code is ManagementErrorCode.CAPABILITY_DENIED

    owner = context()
    first = store.create(owner, kind="test.first", cancellable=False)
    with pytest.raises(ManagementError) as full:
        store.create(owner, kind="test.second", cancellable=False)
    assert full.value.code is ManagementErrorCode.OPERATION_ALREADY_RUNNING
    store.succeed(first.id, {"ok": True})
    second = store.create(owner, kind="test.second", cancellable=False)
    assert second.id != first.id
    with pytest.raises(ManagementError) as cannot_cancel:
        store.cancel(owner, second.id)
    assert cannot_cancel.value.code is ManagementErrorCode.INVALID_OPERATION_STATE


def test_operation_failure_does_not_store_worker_exception_text():
    store = OperationStore()
    owner = context()
    operation = store.create(owner, kind="test.failure", cancellable=False)
    failed = store.fail(
        operation.id,
        code=ManagementErrorCode.UPSTREAM_ERROR,
        message="upstream exposed fake-token-value",
        retryable=True,
    )
    assert failed.error is not None
    assert failed.error.message == "UPSTREAM_ERROR"
    assert "fake-token-value" not in repr(failed)


def test_registry_delegates_to_existing_starter_without_creating_a_worker():
    store = OperationStore()
    registry = OperationRegistry(store)
    calls: list[tuple[str, str, object]] = []

    def existing_starter(operation_id, ctx, payload):
        calls.append((operation_id, ctx.request_id, payload))

    registry.register("domain.existing", existing_starter)
    operation = registry.create(
        context(),
        kind="domain.existing",
        payload={"resourceId": "r-1"},
        cancellable=True,
    )
    assert calls == [(operation.id, "req-test", {"resourceId": "r-1"})]
    assert store.get(context(), operation.id).status is OperationStatus.QUEUED
    with pytest.raises(ValueError):
        registry.register("domain.existing", existing_starter)


def test_registry_maps_unstable_starter_exception_and_marks_operation_failed():
    store = OperationStore()
    registry = OperationRegistry(store)
    original = RuntimeError("provider scheduling internals")

    def broken_starter(operation_id, ctx, payload):
        raise original

    registry.register("domain.broken", broken_starter)
    with pytest.raises(ManagementError) as caught:
        registry.create(
            context(),
            kind="domain.broken",
            payload={"resourceId": "r-1"},
            cancellable=True,
        )
    error = caught.value
    assert error.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
    assert error.retryable is True
    assert error.operation_id is not None
    assert error.__cause__ is original
    assert "scheduling internals" not in str(error)

    operation = store.get(context(), error.operation_id)
    assert operation.status is OperationStatus.FAILED
    assert operation.cancellable is False
    assert operation.error is not None
    assert operation.error.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
    assert operation.error.retryable is True
    assert "scheduling internals" not in repr(operation)


def test_registry_preserves_stable_starter_error_with_created_operation_id():
    store = OperationStore()
    registry = OperationRegistry(store)
    original = ManagementError(
        ManagementErrorCode.UPSTREAM_TIMEOUT,
        retryable=True,
        operation_id="unrelated-operation",
    )

    def stable_failure(operation_id, ctx, payload):
        raise original

    registry.register("domain.timeout", stable_failure)
    with pytest.raises(ManagementError) as caught:
        registry.create(
            context(),
            kind="domain.timeout",
            payload=None,
            cancellable=False,
        )
    error = caught.value
    assert error.code is ManagementErrorCode.UPSTREAM_TIMEOUT
    assert error.retryable is True
    assert error.operation_id not in {None, "unrelated-operation"}
    assert error.__cause__ is original

    operation = store.get(context(), error.operation_id)
    assert operation.status is OperationStatus.FAILED
    assert operation.error is not None
    assert operation.error.code is ManagementErrorCode.UPSTREAM_TIMEOUT
    assert operation.error.retryable is True

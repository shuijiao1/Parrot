"""Bounded management Operation lifecycle without owning a worker pool."""

from __future__ import annotations

import copy
import secrets
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Callable, Mapping

from src.management_auth.policy import CapabilityDenied, authorize
from src.management_auth.principal import Capability

from .context import AuditSink, ManagementContext, audit_record
from .errors import ManagementError, ManagementErrorCode


class OperationStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


_TERMINAL = {
    OperationStatus.SUCCEEDED,
    OperationStatus.FAILED,
    OperationStatus.CANCELLED,
}
_SENSITIVE_KEYS = {
    "apikey",
    "accesstoken",
    "refreshtoken",
    "credential",
    "exchangesecret",
    "managementkey",
    "password",
    "secret",
    "sessiontoken",
    "token",
}


def _public_value(value: Any) -> Any:
    """Recursively redact credential-shaped fields before they reach a store."""
    if isinstance(value, Mapping):
        public: dict[str, Any] = {}
        for key, item in value.items():
            normalized = "".join(ch for ch in str(key).lower() if ch.isalnum())
            public[str(key)] = "[REDACTED]" if normalized in _SENSITIVE_KEYS else _public_value(item)
        return public
    if isinstance(value, (list, tuple)):
        return [_public_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@dataclass(frozen=True, slots=True)
class OperationProgress:
    current: int
    total: int
    message_code: str

    def __post_init__(self) -> None:
        if self.current < 0 or self.total < 0 or self.current > self.total:
            raise ValueError("invalid operation progress")
        if not self.message_code:
            raise ValueError("message_code must not be empty")


@dataclass(frozen=True, slots=True)
class OperationFailure:
    code: ManagementErrorCode
    message: str
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class ManagementOperation:
    id: str
    kind: str
    status: OperationStatus
    actor_subject_id: str
    session_id: str | None
    progress: OperationProgress | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    result: Any
    error: OperationFailure | None
    cancellable: bool


Clock = Callable[[], datetime]
OperationStarter = Callable[[str, ManagementContext, Any], None]


class OperationStore:
    """Thread-safe bounded lifecycle store; execution remains with existing workers."""

    def __init__(
        self,
        *,
        max_operations: int = 500,
        clock: Clock | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        if max_operations < 1:
            raise ValueError("max_operations must be positive")
        self._max_operations = max_operations
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._audit_sink = audit_sink
        self._items: OrderedDict[str, ManagementOperation] = OrderedDict()
        self._lock = RLock()

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("operation clock must return timezone-aware datetimes")
        return now

    @staticmethod
    def _authorize(context: ManagementContext, capability: Capability) -> None:
        try:
            authorize(context.actor, capability)
        except CapabilityDenied as exc:
            raise ManagementError(ManagementErrorCode.CAPABILITY_DENIED) from exc

    def _audit(self, context: ManagementContext, action: str, target: str, result: str) -> None:
        if self._audit_sink is not None:
            self._audit_sink.record(
                audit_record(
                    context,
                    action=action,
                    target=target,
                    result=result,
                    occurred_at=self._now(),
                )
            )

    def _make_room(self) -> None:
        while len(self._items) >= self._max_operations:
            terminal_id = next(
                (item_id for item_id, item in self._items.items() if item.status in _TERMINAL),
                None,
            )
            if terminal_id is None:
                raise ManagementError(
                    ManagementErrorCode.OPERATION_ALREADY_RUNNING,
                    retryable=True,
                )
            del self._items[terminal_id]

    def create(
        self,
        context: ManagementContext,
        *,
        kind: str,
        cancellable: bool,
    ) -> ManagementOperation:
        self._authorize(context, Capability.WRITE)
        if not kind or len(kind) > 120:
            raise ManagementError(ManagementErrorCode.VALIDATION_FAILED)
        with self._lock:
            self._make_room()
            operation_id = f"op_{secrets.token_urlsafe(18)}"
            operation = ManagementOperation(
                id=operation_id,
                kind=kind,
                status=OperationStatus.QUEUED,
                actor_subject_id=context.actor.subject_id,
                session_id=context.actor.session_id,
                progress=None,
                created_at=self._now(),
                started_at=None,
                finished_at=None,
                result=None,
                error=None,
                cancellable=bool(cancellable),
            )
            self._items[operation_id] = operation
        self._audit(context, "operation.create", operation_id, "queued")
        return self._snapshot(operation)

    def _visible(self, context: ManagementContext, operation: ManagementOperation) -> bool:
        if operation.session_id is not None:
            return operation.session_id == context.actor.session_id
        return operation.actor_subject_id == context.actor.subject_id

    def _lookup_visible(self, context: ManagementContext, operation_id: str) -> ManagementOperation:
        operation = self._items.get(operation_id)
        if operation is None or not self._visible(context, operation):
            raise ManagementError(ManagementErrorCode.OPERATION_NOT_FOUND)
        return operation

    @staticmethod
    def _snapshot(operation: ManagementOperation) -> ManagementOperation:
        return replace(
            operation,
            result=copy.deepcopy(operation.result),
            error=copy.deepcopy(operation.error),
        )

    def get(self, context: ManagementContext, operation_id: str) -> ManagementOperation:
        self._authorize(context, Capability.READ)
        with self._lock:
            return self._snapshot(self._lookup_visible(context, operation_id))

    def mark_running(self, operation_id: str) -> ManagementOperation:
        with self._lock:
            operation = self._items.get(operation_id)
            if operation is None:
                raise ManagementError(ManagementErrorCode.OPERATION_NOT_FOUND)
            if operation.status is not OperationStatus.QUEUED:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            operation = replace(
                operation,
                status=OperationStatus.RUNNING,
                started_at=self._now(),
            )
            self._items[operation_id] = operation
            return self._snapshot(operation)

    def update_progress(
        self,
        operation_id: str,
        *,
        current: int,
        total: int,
        message_code: str,
    ) -> ManagementOperation:
        progress = OperationProgress(current=current, total=total, message_code=message_code)
        with self._lock:
            operation = self._items.get(operation_id)
            if operation is None:
                raise ManagementError(ManagementErrorCode.OPERATION_NOT_FOUND)
            if operation.status is not OperationStatus.RUNNING:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            operation = replace(operation, progress=progress)
            self._items[operation_id] = operation
            return self._snapshot(operation)

    def succeed(self, operation_id: str, result: Any = None) -> ManagementOperation:
        with self._lock:
            operation = self._items.get(operation_id)
            if operation is None:
                raise ManagementError(ManagementErrorCode.OPERATION_NOT_FOUND)
            if operation.status not in {OperationStatus.QUEUED, OperationStatus.RUNNING}:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            operation = replace(
                operation,
                status=OperationStatus.SUCCEEDED,
                result=_public_value(result),
                error=None,
                finished_at=self._now(),
                cancellable=False,
            )
            self._items[operation_id] = operation
            return self._snapshot(operation)

    def fail(
        self,
        operation_id: str,
        *,
        code: ManagementErrorCode,
        message: str,
        retryable: bool = False,
    ) -> ManagementOperation:
        with self._lock:
            operation = self._items.get(operation_id)
            if operation is None:
                raise ManagementError(ManagementErrorCode.OPERATION_NOT_FOUND)
            if operation.status not in {OperationStatus.QUEUED, OperationStatus.RUNNING}:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            operation = replace(
                operation,
                status=OperationStatus.FAILED,
                result=None,
                # Worker exception text is intentionally not persisted: it may embed
                # credentials or upstream payloads.  The stable code is safe to expose.
                error=OperationFailure(code=code, message=code.value, retryable=retryable),
                finished_at=self._now(),
                cancellable=False,
            )
            self._items[operation_id] = operation
            return self._snapshot(operation)

    def cancel(self, context: ManagementContext, operation_id: str) -> None:
        self._authorize(context, Capability.WRITE)
        with self._lock:
            operation = self._lookup_visible(context, operation_id)
            if operation.status not in {OperationStatus.QUEUED, OperationStatus.RUNNING}:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            if not operation.cancellable:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            self._items[operation_id] = replace(
                operation,
                status=OperationStatus.CANCELLED,
                finished_at=self._now(),
                cancellable=False,
            )
        self._audit(context, "operation.cancel", operation_id, "cancelled")

    def interrupt_active(self) -> int:
        """Mark lifecycle-owned active records failed during orderly shutdown."""
        changed = 0
        with self._lock:
            for operation_id, operation in tuple(self._items.items()):
                if operation.status in {OperationStatus.QUEUED, OperationStatus.RUNNING}:
                    self._items[operation_id] = replace(
                        operation,
                        status=OperationStatus.FAILED,
                        error=OperationFailure(
                            code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
                            message="Operation interrupted by service shutdown",
                            retryable=True,
                        ),
                        finished_at=self._now(),
                        cancellable=False,
                    )
                    changed += 1
        return changed


class OperationRegistry:
    """Registers domain starters while leaving scheduling to their existing owner."""

    def __init__(self, store: OperationStore) -> None:
        self._store = store
        self._starters: dict[str, OperationStarter] = {}
        self._lock = RLock()

    def register(self, kind: str, starter: OperationStarter) -> None:
        if not kind or not callable(starter):
            raise ValueError("kind and callable starter are required")
        with self._lock:
            if kind in self._starters:
                raise ValueError(f"operation kind already registered: {kind}")
            self._starters[kind] = starter

    def create(
        self,
        context: ManagementContext,
        *,
        kind: str,
        payload: Any,
        cancellable: bool,
    ) -> ManagementOperation:
        with self._lock:
            starter = self._starters.get(kind)
        if starter is None:
            raise ManagementError(ManagementErrorCode.UNSUPPORTED_VALUE)
        operation = self._store.create(context, kind=kind, cancellable=cancellable)
        try:
            starter(operation.id, context, payload)
        except ManagementError as exc:
            self._store.fail(
                operation.id,
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            )
            raise ManagementError(
                exc.code,
                exc.message,
                fields=exc.fields,
                retryable=exc.retryable,
                operation_id=operation.id,
            ) from exc
        except Exception as exc:
            self._store.fail(
                operation.id,
                code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
                message="Operation could not be scheduled",
                retryable=True,
            )
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
                retryable=True,
                operation_id=operation.id,
            ) from exc
        return operation

"""Transport-neutral request context and audit contracts."""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Protocol

from src.management_auth.principal import ManagementPrincipal


@dataclass(frozen=True, slots=True)
class ManagementContext:
    request_id: str
    actor: ManagementPrincipal
    idempotency_key: str | None = None

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id must not be empty")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    actor: str
    action: str
    target: str
    result: str
    request_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        for value in (self.actor, self.action, self.target, self.result, self.request_id):
            if not value:
                raise ValueError("audit fields must not be empty")


class AuditSink(Protocol):
    def record(self, record: AuditRecord) -> None: ...


class PersistentAuditStore(Protocol):
    def record_audit(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        result: str,
        request_id: str,
    ) -> None: ...


class StoreAuditSink:
    """Audit sink backed by the single-purpose management state store."""

    def __init__(self, store: PersistentAuditStore) -> None:
        self._store = store

    def record(self, record: AuditRecord) -> None:
        # Audit storage is ancillary: failure cannot undo a committed mutation
        # or suppress its one-time secret response. Do not log record contents.
        try:
            self._store.record_audit(
                actor=record.actor,
                action=record.action,
                target=record.target,
                result=record.result,
                request_id=record.request_id,
            )
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Management audit write failed (%s)", type(exc).__name__,
            )


class BoundedAuditSink:
    """A deterministic bounded sink useful for ephemeral deployments and tests."""

    def __init__(self, max_records: int = 1_000) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self._records: deque[AuditRecord] = deque(maxlen=max_records)
        self._lock = RLock()

    def record(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)

    def snapshot(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._records)


def audit_record(
    context: ManagementContext,
    *,
    action: str,
    target: str,
    result: str,
    occurred_at: datetime | None = None,
) -> AuditRecord:
    return AuditRecord(
        actor=context.actor.subject_id,
        action=action,
        target=target,
        result=result,
        request_id=context.request_id,
        occurred_at=occurred_at or datetime.now(timezone.utc),
    )

"""Bounded one-shot OAuth flow/plan storage.

The store is transport neutral. Public tokens are random bearer capabilities; only a
SHA-256 verifier is retained for ordinary plans. Import/login payloads may contain
credentials and therefore remain process-local, bounded, short-lived, and are never
placed in Operation results or audit details.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Callable, Generic, TypeVar

from src.management_control.errors import ManagementError, ManagementErrorCode


PayloadT = TypeVar("PayloadT")
Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class StoredPlan(Generic[PayloadT]):
    plan_id: str
    actor_subject_id: str
    kind: str
    revision: str
    payload: PayloadT
    expires_at: datetime


@dataclass(slots=True)
class _Record(Generic[PayloadT]):
    plan: StoredPlan[PayloadT]
    verifier: bytes


class OneShotPlanStore(Generic[PayloadT]):
    def __init__(
        self,
        *,
        prefix: str,
        ttl_seconds: int = 600,
        max_items: int = 256,
        clock: Clock | None = None,
    ) -> None:
        if not prefix or ttl_seconds < 1 or max_items < 1:
            raise ValueError("invalid one-shot plan store settings")
        self._prefix = prefix
        self._ttl = timedelta(seconds=ttl_seconds)
        self._max_items = max_items
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._records: OrderedDict[str, _Record[PayloadT]] = OrderedDict()
        self._lock = RLock()

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("plan clock must be timezone-aware")
        return now

    @staticmethod
    def _digest(secret: str) -> bytes:
        return hashlib.sha256(secret.encode("utf-8")).digest()

    def _prune(self, now: datetime) -> None:
        for plan_id, record in tuple(self._records.items()):
            if record.plan.expires_at <= now:
                del self._records[plan_id]
        while len(self._records) >= self._max_items:
            self._records.popitem(last=False)

    def create(
        self,
        *,
        actor_subject_id: str,
        kind: str,
        revision: str,
        payload: PayloadT,
    ) -> tuple[str, StoredPlan[PayloadT]]:
        now = self._now()
        plan_id = f"{self._prefix}_{secrets.token_urlsafe(12)}"
        secret = secrets.token_urlsafe(24)
        token = f"{plan_id}.{secret}"
        plan = StoredPlan(
            plan_id=plan_id,
            actor_subject_id=actor_subject_id,
            kind=kind,
            revision=revision,
            payload=payload,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._prune(now)
            self._records[plan_id] = _Record(plan=plan, verifier=self._digest(secret))
        return token, plan

    def _resolve(
        self,
        token: str,
        *,
        actor_subject_id: str,
        kind: str,
        consume: bool,
    ) -> StoredPlan[PayloadT]:
        plan_id, separator, secret = str(token or "").partition(".")
        # Always hash a value and compare a same-sized digest before returning a
        # public failure, avoiding a fast path for malformed/unknown tokens.
        supplied = self._digest(secret if separator else "")
        now = self._now()
        with self._lock:
            record = self._records.get(plan_id)
            expected = record.verifier if record is not None else bytes(len(supplied))
            valid = hmac.compare_digest(supplied, expected)
            if record is None or not valid:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            plan = record.plan
            if plan.expires_at <= now:
                del self._records[plan_id]
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            if plan.actor_subject_id != actor_subject_id or plan.kind != kind:
                raise ManagementError(ManagementErrorCode.INVALID_OPERATION_STATE)
            if consume:
                del self._records[plan_id]
            return plan

    def inspect(self, token: str, *, actor_subject_id: str, kind: str) -> StoredPlan[PayloadT]:
        return self._resolve(
            token,
            actor_subject_id=actor_subject_id,
            kind=kind,
            consume=False,
        )

    def consume(self, token: str, *, actor_subject_id: str, kind: str) -> StoredPlan[PayloadT]:
        return self._resolve(
            token,
            actor_subject_id=actor_subject_id,
            kind=kind,
            consume=True,
        )

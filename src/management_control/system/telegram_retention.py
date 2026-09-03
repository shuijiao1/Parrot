"""Compatibility adapter that drives frozen Telegram retention UI through P4 control."""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable

from src import config, log_db
from src.management_control.context import ManagementContext
from src.management_control.errors import ManagementError
from src.management_control.observability.retention import RetentionControl, RetentionMode
from src.management_control.operations import OperationStore


class _CapturingLogDb:
    """Delegate to log_db while retaining data needed only by the frozen TG renderer."""

    def __init__(self, module=log_db) -> None:
        self.module = module
        self.last_plan: dict[str, Any] | None = None
        self.last_policy_result: dict[str, Any] | None = None
        self.last_apply_result: dict[str, Any] | None = None
        self.last_exception: Exception | None = None
        self.progress: Callable[[dict[str, Any]], None] | None = None
        self._lock = threading.RLock()

    def __getattr__(self, name: str):
        return getattr(self.module, name)

    def plan_retention(self, days: int) -> dict[str, Any]:
        try:
            value = self.module.plan_retention(days)
        except Exception as exc:
            with self._lock:
                self.last_exception = exc
            raise
        with self._lock:
            self.last_plan = copy.deepcopy(value)
        return value

    def extend_retention_days(self, days: int) -> dict[str, Any]:
        value = self.module.extend_retention_days(days)
        with self._lock:
            self.last_policy_result = copy.deepcopy(value)
        return value

    def set_retention_forever(self) -> dict[str, Any]:
        value = self.module.set_retention_forever()
        with self._lock:
            self.last_policy_result = copy.deepcopy(value)
        return value

    def apply_retention_plan(self, plan, *, activate_policy=False, progress=None):
        def combined(event):
            callback = self.progress
            if callback is not None:
                callback(copy.deepcopy(event))
            if progress is not None:
                progress(event)
        value = self.module.apply_retention_plan(
            plan, activate_policy=activate_policy, progress=combined,
        )
        with self._lock:
            self.last_apply_result = copy.deepcopy(value)
        return value


class TelegramRetentionAdapter:
    """Synchronous facade preserving TG call ordering over RetentionControl."""

    def __init__(self) -> None:
        self.gateway = _CapturingLogDb()
        self.control = RetentionControl(
            log_db=self.gateway,
            config=config,
            now=lambda: time.time(),
            ttl_seconds=600,
            start_worker=lambda worker: worker(),
        )
        self.operations = OperationStore(max_operations=64)

    def settings(self, context: ManagementContext) -> dict[str, Any]:
        return self.control.settings(context)

    def set_log_store_bodies(self, context: ManagementContext, value: bool) -> dict[str, Any]:
        return self.control.update_settings(
            context,
            mode=None,
            days=None,
            log_store_bodies=value,
            expected_revision=None,
        )

    def extend_days(self, context: ManagementContext, days: int) -> dict[str, Any]:
        self.gateway.last_policy_result = None
        try:
            self.control.update_settings(
                context,
                mode=RetentionMode.DAYS,
                days=days,
                log_store_bodies=None,
                expected_revision=None,
            )
        except ManagementError:
            pass
        return copy.deepcopy(self.gateway.last_policy_result or {"ok": False})

    def set_forever(self, context: ManagementContext) -> dict[str, Any]:
        self.gateway.last_policy_result = None
        try:
            self.control.update_settings(
                context,
                mode=RetentionMode.FOREVER,
                days=None,
                log_store_bodies=None,
                expected_revision=None,
            )
        except ManagementError:
            pass
        return copy.deepcopy(self.gateway.last_policy_result or {"ok": False})

    def create_plan(self, context: ManagementContext, days: int) -> tuple[dict[str, Any], str | None, str | None]:
        self.gateway.last_plan = None
        self.gateway.last_exception = None
        public = None
        try:
            public = self.control.create_plan(context, days=days)
        except ManagementError:
            if self.gateway.last_exception is not None:
                raise self.gateway.last_exception
        raw = copy.deepcopy(self.gateway.last_plan or {})
        return raw, (str(public["id"]) if public else None), (str(public["revision"]) if public else None)

    def commit_plan(
        self,
        context: ManagementContext,
        plan_id: str,
        revision: str,
        *,
        progress: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        self.gateway.last_apply_result = None
        self.gateway.progress = progress
        try:
            self.control.commit_plan(
                context, plan_id, expected_revision=revision, operations=self.operations,
            )
        finally:
            self.gateway.progress = None
        return copy.deepcopy(self.gateway.last_apply_result or {"ok": False})

    def cancel_plan(self, context: ManagementContext, plan_id: str) -> None:
        try:
            self.control.cancel_plan(context, plan_id)
        except ManagementError:
            pass


DEFAULT_TELEGRAM_RETENTION_ADAPTER = TelegramRetentionAdapter()

"""Frozen Telegram retention commands over the authoritative log database."""

from __future__ import annotations

from typing import Any, Callable

from src import config, log_db
from src.management_auth import Capability
from src.management_control.context import ManagementContext
from src.management_control.observability.common import require


class TelegramRetentionAdapter:
    """Thin synchronous facade preserving the v0.31.13 Telegram lifecycle.

    The Telegram menu already owns its actor-bound eight-character pending-plan
    store and exact 600-second TTL.  This adapter must therefore never create a
    second plan, TTL, capacity limit, or mutable progress capture.  Management API
    retention continues to use the independent P4 ``RetentionControl``.
    """

    def __init__(self, *, module=log_db, config_module=config) -> None:
        self.log_db = module
        self.config = config_module

    @staticmethod
    def _write(context: ManagementContext, capability: Capability = Capability.WRITE) -> None:
        require(context, capability)

    def settings(self, context: ManagementContext) -> dict[str, Any]:
        require(context, Capability.READ)
        cfg = self.config.get()
        policy = self.log_db.retention_policy(cfg)
        return {
            "mode": policy["mode"],
            "days": policy.get("days"),
            "logStoreBodies": cfg.get("logStoreBodies", True) is not False,
        }

    def set_log_store_bodies(self, context: ManagementContext, value: bool) -> None:
        self._write(context)
        # Exactly the baseline config.update call: raw storage exceptions escape.
        self.config.update(lambda cfg: cfg.__setitem__("logStoreBodies", value))

    def extend_days(self, context: ManagementContext, days: int) -> dict[str, Any]:
        self._write(context)
        return self.log_db.extend_retention_days(days)

    def set_forever(self, context: ManagementContext) -> dict[str, Any]:
        self._write(context)
        return self.log_db.set_retention_forever()

    def create_plan(self, context: ManagementContext, days: int) -> dict[str, Any]:
        self._write(context)
        # Keep the raw cutoff for the frozen renderer's "时间不可表示" fallback.
        return self.log_db.plan_retention(days)

    def commit_plan(
        self,
        context: ManagementContext,
        plan: dict[str, Any],
        *,
        progress: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        self._write(context, Capability.DESTRUCTIVE)
        # The callback remains call-local, so concurrent chats cannot exchange
        # progress events.  RuntimeError and all other authority errors propagate.
        return self.log_db.apply_retention_plan(
            plan, activate_policy=True, progress=progress,
        )


DEFAULT_TELEGRAM_RETENTION_ADAPTER = TelegramRetentionAdapter()

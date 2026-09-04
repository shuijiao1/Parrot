"""Overview and read-only runtime observability queries."""

from __future__ import annotations

import copy
import os
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src import __version__
from src import affinity as affinity_module
from src import apikey_limiter as apikey_limiter_module
from src import concurrency as concurrency_module
from src import config as config_module
from src import cooldown as cooldown_module
from src import load_balancing as load_balancing_module
from src import log_db as log_db_module
from src import network_monitor as network_monitor_module
from src import oauth_manager as oauth_manager_module
from src import public_ip as public_ip_module
from src import quota_errors as quota_errors_module
from src import scorer as scorer_module
from src import state_db as state_db_module
from src import status_monitor as status_monitor_module
from src import update_checker as update_checker_module
from src.channel import registry as registry_module
from src.management_control.context import ManagementContext

from .common import (
    PageResult,
    camelize,
    page_slice,
    require,
    revision_for,
    sanitize_credentials,
    utc_datetime,
)


_BJT = timezone(timedelta(hours=8))
_SERVICE_START_TS = time.time()


def _plain(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class StatusControl:
    def __init__(
        self,
        *,
        config=config_module,
        registry=registry_module,
        cooldown=cooldown_module,
        scorer=scorer_module,
        affinity=affinity_module,
        concurrency=concurrency_module,
        apikey_limiter=apikey_limiter_module,
        log_db=log_db_module,
        oauth_manager=oauth_manager_module,
        quota_errors=quota_errors_module,
        state_db=state_db_module,
        status_monitor=status_monitor_module,
        network_monitor=network_monitor_module,
        public_ip=public_ip_module,
        update_checker=update_checker_module,
        load_balancing=load_balancing_module,
        now=time.time,
        service_started_at: float = _SERVICE_START_TS,
        version: str = __version__,
    ) -> None:
        self.config = config
        self.registry = registry
        self.cooldown = cooldown
        self.scorer = scorer
        self.affinity = affinity
        self.concurrency = concurrency
        self.apikey_limiter = apikey_limiter
        self.log_db = log_db
        self.oauth_manager = oauth_manager
        self.quota_errors = quota_errors
        self.state_db = state_db
        self.status_monitor = status_monitor
        self.network_monitor = network_monitor
        self.public_ip_service = public_ip
        self.update_checker = update_checker
        self.load_balancing = load_balancing
        self._now = now
        self.service_started_at = service_started_at
        self.version = version

    def config_snapshot(self, context: ManagementContext) -> dict[str, Any]:
        require(context)
        return copy.deepcopy(self.config.get())

    def channels(self, context: ManagementContext) -> list[Any]:
        require(context)
        return list(self.registry.all_channels())

    def cooldowns(self, context: ManagementContext) -> list[dict[str, Any]]:
        require(context)
        return copy.deepcopy(self.cooldown.active_entries())

    def scorer_snapshot(self, context: ManagementContext) -> list[dict[str, Any]]:
        require(context)
        return copy.deepcopy(self.scorer.snapshot())

    def affinity_count(self, context: ManagementContext) -> int:
        require(context)
        return int(self.affinity.count())

    def concurrency_snapshot(self, context: ManagementContext) -> dict[str, Any]:
        require(context)
        return {
            "channelTotals": copy.deepcopy(self.concurrency.totals()),
            "channels": copy.deepcopy(self.concurrency.snapshot()),
            "apiKeyTotals": copy.deepcopy(self.apikey_limiter.totals()),
            "apiKeys": copy.deepcopy(self.apikey_limiter.snapshot()),
        }

    def api_concurrency_snapshot(self, context: ManagementContext) -> dict[str, Any]:
        return camelize(self.concurrency_snapshot(context))

    def channel_concurrency_totals(self, context: ManagementContext) -> dict[str, Any]:
        require(context)
        return copy.deepcopy(self.concurrency.totals())

    def stats_summary(self, context: ManagementContext, *, since_ts: float, family: str | None = None) -> dict:
        require(context)
        return copy.deepcopy(self.log_db.stats_summary(
            since_ts=float(since_ts), family=family, summary_top_limit=0, include_cost=False,
        ))

    def tps_by_channel_model(self, context: ManagementContext, *, since_ts: float) -> dict:
        require(context)
        return copy.deepcopy(self.log_db.tps_by_channel_model(since_ts=float(since_ts)))

    def oauth_accounts(self, context: ManagementContext) -> list[dict]:
        require(context)
        return copy.deepcopy(self.oauth_manager.list_accounts())

    def account_key(self, context: ManagementContext, account: dict) -> str:
        require(context)
        return str(self.oauth_manager.get_account_key(account) or "")

    def provider_of(self, context: ManagementContext, account: dict) -> str:
        require(context)
        return str(self.oauth_manager.provider_of(account))

    def fable_display(self, context: ManagementContext, row: dict) -> tuple[float | None, str | None]:
        require(context)
        return self.oauth_manager.fable_display_from_quota_row(row)

    def usage_from_quota(self, context: ManagementContext, row: dict) -> dict:
        require(context)
        return copy.deepcopy(self.oauth_manager.usage_from_quota_row(row))

    def active_quota_cooldown(self, context: ManagementContext, row: dict) -> bool:
        require(context)
        return bool(self.quota_errors.active_quota_cooldown(row))

    def format_quota_reset_bjt(self, context: ManagementContext, value: int) -> str:
        require(context)
        return str(self.quota_errors.format_bjt_ms(value, compact=True))

    def selection_mode(self, context: ManagementContext, value: str) -> str:
        require(context)
        return str(self.load_balancing.display_mode(value))

    def public_ip(self, context: ManagementContext) -> str | None:
        require(context)
        value = self.public_ip_service.get()
        return str(value) if value else None

    def status_summary(self, context: ManagementContext) -> str | None:
        require(context)
        return self.status_monitor.get_active_summary()

    def update_banner(self, context: ManagementContext) -> str | None:
        require(context)
        return self.update_checker.get_update_banner()

    def network_summary(self, context: ManagementContext) -> str | None:
        require(context)
        return self.network_monitor.active_summary()

    def quota_row(self, context: ManagementContext, account_key: str) -> dict | None:
        require(context)
        row = self.state_db.quota_load(account_key)
        return copy.deepcopy(row) if row else None

    def refresh_telegram_quota(self, context: ManagementContext, account_keys: list[str]) -> None:
        """Preserve the frozen TG status refresh; API snapshots never call this."""
        require(context)
        self.oauth_manager.ensure_quota_fresh_sync(list(account_keys))

    def overview(self, context: ManagementContext) -> dict[str, Any]:
        require(context)
        cfg = self.config.get()
        channels = list(self.registry.all_channels())
        accounts = list(self.oauth_manager.list_accounts())
        api_keys = cfg.get("apiKeys") or {}
        now = datetime.fromtimestamp(self._now(), tz=_BJT)
        since = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        try:
            today = self.log_db.stats_summary(
                since_ts=since, family=None, summary_top_limit=0, include_cost=True,
            ).get("overall") or {}
        except Exception:
            today = {}
        try:
            lifetime = self.log_db.stats_lifetime()
            lifetime = lifetime.get("overall") if isinstance(lifetime, dict) and "overall" in lifetime else lifetime
        except Exception:
            lifetime = {}
        quota_hot = 0
        for row in self.state_db.quota_load_all():
            if any(float(row.get(key) or 0) >= 80 for key in (
                "five_hour_util", "seven_day_util", "thirty_day_util",
                "sonnet_util", "opus_util", "codex_primary_used_pct", "codex_secondary_used_pct",
            )):
                quota_hot += 1
        listeners = cfg.get("listen") or {}
        data = {
            "version": self.version,
            "uptimeSeconds": max(0, int(self._now() - self.service_started_at)),
            "listeners": {
                "host": str(listeners.get("host") or ""),
                "port": int(listeners.get("port") or 0),
            },
            "counts": {
                "channels": len(channels),
                "oauthAccounts": len(accounts),
                "apiKeys": len(api_keys) if isinstance(api_keys, dict) else len(api_keys or []),
                "quotaHot": quota_hot,
            },
            "today": camelize(sanitize_credentials(_plain(today or {}))),
            "lifetime": camelize(sanitize_credentials(_plain(lifetime or {}))),
            "activeAlerts": camelize(sanitize_credentials(_plain(self.status_monitor.snapshot_active()))),
        }
        data["revision"] = revision_for(data)
        return data

    @staticmethod
    def _channel_record(channel: Any) -> dict[str, Any]:
        return {
            "id": str(getattr(channel, "key", "")),
            "name": str(getattr(channel, "display_name", "") or getattr(channel, "name", "") or getattr(channel, "key", "")),
            "protocol": str(getattr(channel, "protocol", "") or "unknown"),
            "type": str(getattr(channel, "type", "") or "unknown"),
            "enabled": bool(getattr(channel, "enabled", False)),
            "disabledReason": sanitize_credentials(getattr(channel, "disabled_reason", None)),
        }

    def runtime_status(self, context: ManagementContext) -> dict[str, Any]:
        require(context)
        channels = list(self.registry.all_channels())
        channel_rows = [self._channel_record(channel) for channel in channels]
        by_key = {row["id"]: row for row in channel_rows}
        cooldowns = copy.deepcopy(self.cooldown.active_entries())
        problem_ids = {
            row["id"] for row in channel_rows
            if not row["enabled"] or row["disabledReason"]
        }
        problem_ids.update(str(row.get("channel_key") or "") for row in cooldowns)
        cooldown_pairs = {
            (str(row.get("channel_key") or ""), str(row.get("model") or ""))
            for row in cooldowns
        }
        fastest: dict[str, list[dict[str, Any]]] = {"anthropic": [], "openai": []}
        for stat in self.scorer.snapshot():
            key = str(stat.get("channel_key") or "")
            channel = by_key.get(key)
            if not channel or not channel["enabled"] or channel["disabledReason"]:
                continue
            model = str(stat.get("model") or "")
            if (key, model) in cooldown_pairs:
                continue
            requests = int(stat.get("recent_requests") or 0)
            successes = int(stat.get("recent_success_count") or 0)
            if requests <= 0 or successes / requests < .5:
                continue
            family = "openai" if "openai" in channel["protocol"].lower() else "anthropic"
            fastest[family].append({
                "channelId": key,
                "model": model,
                "successRate": successes / requests,
                "score": float(stat.get("score") or 0),
                "averageFirstByteMilliseconds": stat.get("avg_first_byte_ms"),
            })
        for values in fastest.values():
            values.sort(key=lambda item: item["score"])
            del values[5:]
        concurrency = camelize(self.concurrency_snapshot(context))
        data = {
            "channels": channel_rows,
            "problemChannels": [by_key[key] for key in sorted(problem_ids) if key in by_key],
            "fastestByFamily": fastest,
            "quotaWarnings": self._quota_warning_records(context),
            "concurrency": concurrency,
            "cooldownSummary": {
                "active": len(cooldowns),
                "permanent": sum(1 for row in cooldowns if row.get("cooldown_until") == -1),
            },
            "affinitySummary": {
                "server": int(self.affinity.count()),
                "client": int(self.affinity.client_count()),
            },
            "database": camelize(sanitize_credentials(self._database_status())),
        }
        data["revision"] = revision_for(data)
        return data

    def _quota_warning_records(self, context: ManagementContext) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for account in self.oauth_accounts(context):
            key = str(self.oauth_manager.get_account_key(account) or "")
            row = self.quota_row(context, key)
            if not row:
                continue
            metrics = []
            for name, field in (
                ("fiveHour", "five_hour_util"), ("sevenDay", "seven_day_util"),
                ("thirtyDay", "thirty_day_util"), ("sonnet", "sonnet_util"),
                ("opus", "opus_util"), ("primary", "codex_primary_used_pct"),
                ("secondary", "codex_secondary_used_pct"),
            ):
                value = row.get(field)
                if value is not None and float(value) >= 80:
                    metrics.append({"window": name, "utilizationPercent": float(value)})
            if metrics:
                records.append({
                    "accountId": key,
                    "provider": str(self.oauth_manager.provider_of(account)),
                    "metrics": metrics,
                })
        return records

    def _database_status(self) -> dict[str, Any]:
        try:
            health = _plain(self.state_db.health())
            return {"status": "healthy", "state": health}
        except Exception:
            return {"status": "unavailable", "state": {}}

    def cooldown_page(self, context: ManagementContext, *, page: int, page_size: int) -> PageResult[dict]:
        rows = self.cooldowns(context)
        normalized = []
        for row in rows:
            until = int(row.get("cooldown_until") or 0)
            normalized.append({
                "channelId": str(row.get("channel_key") or ""),
                "model": str(row.get("model") or ""),
                "errorCount": int(row.get("error_count") or 0),
                "state": "permanent" if until == -1 else "active",
                "until": None if until == -1 else utc_datetime(until / 1000),
                "message": sanitize_credentials(str(row.get("message") or "")) or None,
            })
        return page_slice(normalized, page=page, page_size=page_size)

    def background_jobs(self, context: ManagementContext, *, page: int, page_size: int) -> PageResult[dict]:
        """Describe configured jobs without inventing scheduler telemetry.

        The runtime currently exposes no authoritative last/next/run-state
        registry.  Therefore enabled jobs are ``unknown``; only explicit
        configuration or the process-wide no-refresh guard proves ``disabled``.
        """
        require(context)
        cfg = self.config.get()
        affinity_cfg = cfg.get("affinity") or {}
        quota_cfg = cfg.get("quotaMonitor") or {}
        recovery_cfg = cfg.get("cooldownRecovery") or {}
        no_refresh = os.environ.get("PARROT_NO_REFRESH") == "1"
        model_sync_interval = getattr(
            self.oauth_manager, "OAUTH_MODEL_SYNC_CHECK_INTERVAL_SECONDS", None,
        )
        jobs = [
            ("walCheckpoint", None, False),
            ("pendingCleanup", None, False),
            ("affinityCleanup", affinity_cfg.get("cleanupIntervalSeconds"), False),
            ("oauthRefresh", None, no_refresh),
            (
                "quotaMonitor", quota_cfg.get("intervalSeconds"),
                no_refresh or not bool(quota_cfg.get("enabled", False)),
            ),
            ("oauthModelSync", model_sync_interval, no_refresh),
            (
                "cooldownProbe", recovery_cfg.get("intervalSeconds"),
                not bool(recovery_cfg.get("enabled", True)),
            ),
            ("providerUsage", None, no_refresh),
        ]
        rows = [{
            "id": name,
            "intervalSeconds": int(interval) if interval is not None else None,
            "lastRunAt": None,
            "nextRunAt": None,
            "status": "disabled" if disabled else "unknown",
            "error": None,
        } for name, interval, disabled in jobs]
        return page_slice(rows, page=page, page_size=page_size)


DEFAULT_STATUS_CONTROL = StatusControl()

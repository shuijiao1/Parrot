"""Transport-neutral runtime queries used by the legacy system menu adapter."""

from __future__ import annotations

from typing import Any, Mapping

from src import (
    apikey_limiter as apikey_limiter_module,
    concurrency as concurrency_module,
    config as config_module,
    log_db as log_db_module,
    network as network_module,
    network_monitor as network_monitor_module,
    state_db as state_db_module,
)
from src.management_control.context import AuditSink
from src.management_control.models.common import DomainControl


class SystemRuntimeControl(DomainControl):
    """Own the system menu's runtime/config query boundary.

    These compatibility queries intentionally preserve the legacy return shapes
    and raw exception behavior.  Telegram remains responsible for rendering,
    callback state and transport ordering.
    """

    def __init__(
        self,
        *,
        config=config_module,
        log_db=log_db_module,
        network=network_module,
        network_monitor=network_monitor_module,
        state_db=state_db_module,
        concurrency=concurrency_module,
        apikey_limiter=apikey_limiter_module,
        audit_sink: AuditSink | None = None,
    ) -> None:
        super().__init__(audit_sink=audit_sink)
        self.config = config
        self.log_db = log_db
        self.network = network
        self.network_monitor = network_monitor
        self.state_db = state_db
        self.concurrency = concurrency
        self.apikey_limiter = apikey_limiter

    def config_snapshot(self) -> dict[str, Any]:
        self._read(None)
        return self.config.get()

    def retention_policy(self, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
        self._read(None)
        return self.log_db.retention_policy(cfg)

    def retention_cleanup_busy(self) -> bool:
        self._read(None)
        return self.log_db.retention_cleanup_busy()

    def proxy_stats(self, *, limit: int) -> list[dict[str, Any]]:
        self._read(None)
        return self.log_db.proxy_stats(limit=limit)

    def dns_cache_entries(self) -> list[dict[str, Any]]:
        self._read(None)
        return self.network.dns_cache_entries()

    def dns_servers(self) -> list[str]:
        self._read(None)
        return self.network.dns_servers()

    def dumps_network_state(self, value: Mapping[str, Any]) -> dict[str, Any]:
        self._read(None)
        return self.network.dumps_state(dict(value))

    def dns_test_text(self, test: dict[str, Any]) -> str:
        self._read(None)
        return self.network.dns_test_text(test)

    def socks5_test_text(self, test: dict[str, Any]) -> str:
        self._read(None)
        return self.network.socks5_test_text(test)

    def failure_warning(self, kind: str, test: dict[str, Any]) -> str:
        self._read(None)
        return self.network.failure_warning(kind, test)

    def socks5_config(self) -> dict[str, Any]:
        self._read(None)
        return self.network.socks5_cfg()

    def mask_network_url(self, url: str) -> str:
        self._read(None)
        return self.network.mask_url(url)

    def monitor_config(self) -> dict[str, Any]:
        self._read(None)
        return self.network_monitor.cfg()

    def network_checks(self) -> list[dict[str, Any]]:
        self._read(None)
        return self.state_db.network_check_load_all()

    def active_monitor_failures(self) -> list[dict[str, Any]]:
        self._read(None)
        return self.network_monitor.active_failures()

    def enabled_monitor_channels(self) -> set[str]:
        self._read(None)
        return self.network_monitor.enabled_channel_keys()

    def channel_probe_url(self, channel: Any) -> str:
        self._read(None)
        return self.network_monitor._channel_probe_url(channel)

    def monitor_channel_enabled(self, key: str) -> bool:
        self._read(None)
        return self.network_monitor.channel_enabled(key)

    def format_monitor_results(self, results: Any) -> str:
        self._read(None)
        return self.network_monitor.format_results(results)

    def concurrency_runtime(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self._read(None)
        return self.concurrency.totals(), self.concurrency.snapshot()

    def api_key_runtime(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self._read(None)
        return self.apikey_limiter.totals(), self.apikey_limiter.snapshot()


DEFAULT_SYSTEM_RUNTIME_CONTROL = SystemRuntimeControl()

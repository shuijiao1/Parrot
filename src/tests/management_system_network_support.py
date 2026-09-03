"""In-memory P6 control/API fixture; no real DNS, socket, config or state I/O."""

from __future__ import annotations

import copy
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from src import config as config_module
from src.management_api.routers.content_blacklist import router as blacklist_router
from src.management_api.routers.network import router as network_router
from src.management_api.routers.system_settings import router as settings_router
from src.management_api.routers.system_support import (
    SystemNetworkControls,
    get_bound_system_network_controls,
)
from src.management_control import BoundedAuditSink
from src.management_control.network import NetworkControl
from src.management_control.system import ContentBlacklistControl, SettingsControl
from src.tests.test_management_api_foundation import bearer, build_app, create_session


class FakeConfig:
    def __init__(self) -> None:
        self.value = copy.deepcopy(config_module.DEFAULT_CONFIG)
        self.value["channels"] = [{
            "name": "example", "baseUrl": "https://upstream.invalid",
            "apiKey": "test-marker-channel-key", "models": ["model-a"],
        }]
        self.value["network"]["socks5"] = {
            "enabled": True,
            "url": "socks5://alpha-marker:password-marker@proxy.invalid:1080",
        }
        self.updates = 0
        self._lock = threading.RLock()

    def get(self):
        return self.value

    def update(self, mutator, **_kwargs):
        with self._lock:
            candidate = copy.deepcopy(self.value)
            mutator(candidate)
            self.value = candidate
            self.updates += 1
            return self.value

    @contextmanager
    def serialized_updates(self):
        with self._lock:
            yield


class FakeRegistry:
    def __init__(self) -> None:
        self.items = [SimpleNamespace(key="api:example", display_name="example", type="api")]

    def all_channels(self):
        return list(self.items)


class FakeNetworkGateway:
    def __init__(self, config: FakeConfig, registry: FakeRegistry) -> None:
        self.config = config
        self.registry = registry
        self.dns_passes = True
        self.socks_passes = True
        self.events: list[tuple] = []
        self.cache = [{
            "host": "public.example", "family": 2, "servers": ["1.1.1.1"],
            "ips": ["192.0.2.10"], "expires_at_epoch": 1_893_456_000.0,
            "ttl_remaining_seconds": 45,
        }]
        self.history = [{
            "key": "dns", "label": "DNS", "category": "dns", "ok": False,
            "detail": (
                "TOKEN=generic-marker api_token=snake-marker sessionSecret=camel-marker "
                "AUTHORIZATION=Bearer auth-marker cookie=cookie-marker "
                "escaped={\\\"refreshToken\\\":\\\"escaped-marker\\\"} "
                "url=socks5://username-only-marker@proxy.invalid:1080 "
                "Basic business words monkey hockey turkey donkey passkey keyboard"
            ),
            "latency_ms": None, "checked_at": 1_767_326_400_000,
        }]

    def config_get(self):
        return self.config.get()

    def serialized_updates(self):
        return self.config.serialized_updates()

    def normalize_dns(self, servers):
        values = []
        for item in servers:
            value = str(item).strip()
            if not value or value.startswith("bad"):
                raise ValueError("invalid DNS")
            if value not in values:
                values.append(value)
        if not values:
            raise ValueError("missing DNS")
        return values

    def parse_dns_text(self, value):
        return self.normalize_dns([item.strip() for item in value.replace("，", ",").split(",")])

    def test_dns(self, servers):
        self.events.append(("dns.test", tuple(servers)))
        return {
            "ok": self.dns_passes,
            "servers": list(servers),
            "results": [{
                "host": "public.example", "resolve": self.dns_passes,
                "error": "apiToken=test-marker-dns" if not self.dns_passes else "",
            }],
        }

    def save_dns(self, servers):
        self.events.append(("dns.save", tuple(servers)))
        self.config.update(lambda root: root.setdefault("network", {}).setdefault("dns", {}).__setitem__("servers", list(servers)))

    def sync_system_dns(self):
        servers = ["9.9.9.9"]
        self.events.append(("dns.sync",))
        self.save_dns(servers)
        return servers

    def dns_cache(self):
        return copy.deepcopy(self.cache)

    def clear_dns_cache(self):
        self.events.append(("dns.cache.clear",))
        self.cache.clear()

    def normalize_socks5(self, url):
        value = str(url).strip()
        if "://" not in value:
            value = "socks5://" + value
        parsed = urlsplit(value)
        if parsed.scheme not in {"socks5", "tcp"} or not parsed.hostname or parsed.port is None:
            raise ValueError("invalid SOCKS5")
        if parsed.scheme == "tcp":
            value = "socks5://" + value.split("://", 1)[1]
        return SimpleNamespace(url=value)

    async def test_socks5(self, url):
        self.events.append(("socks5.test", url))
        return {
            "ok": self.socks_passes,
            "url": url,
            "display_url": url,
            "results": [{
                "label": "proxy", "ok": self.socks_passes,
                "error": "AUTHORIZATION: Bearer test-marker-bearer" if not self.socks_passes else "",
            }],
        }

    def save_socks5(self, url, *, enabled):
        self.events.append(("socks5.save", url, enabled))
        self.config.update(lambda root: root.setdefault("network", {}).__setitem__("socks5", {"url": url, "enabled": enabled}))
        return url

    def set_socks5_enabled(self, enabled):
        self.events.append(("socks5.enable", enabled))
        self.config.update(lambda root: root.setdefault("network", {}).setdefault("socks5", {}).__setitem__("enabled", enabled))

    def channels(self):
        return self.registry.all_channels()

    def monitor_config(self):
        return copy.deepcopy(self.config.get().setdefault("network", {}).setdefault("monitor", {}))

    def update_monitor(self, mutator):
        self.events.append(("monitor.update",))
        self.config.update(lambda root: mutator(root.setdefault("network", {}).setdefault("monitor", {})))

    def set_monitor_channel(self, channel_id, enabled):
        self.update_monitor(lambda mon: mon.setdefault("channels", {"enabled": False, "byKey": {}}).setdefault("byKey", {}).__setitem__(channel_id, enabled))

    @contextmanager
    def monitor_transaction(self):
        with self.config.serialized_updates():
            yield

    def checks(self):
        return copy.deepcopy(self.history)

    async def run_monitor(self):
        self.events.append(("monitor.run",))
        return [{
            "key": "dns", "label": "DNS", "category": "dns", "ok": False,
            "detail": "refreshToken=test-marker-refresh",
            "latencyMilliseconds": None,
        }]

    def format_monitor_result(self, item):
        return dict(item)


class P6Fixture:
    def __init__(self, runtime) -> None:
        self.config = FakeConfig()
        self.registry = FakeRegistry()
        self.gateway = FakeNetworkGateway(self.config, self.registry)
        self.audit = BoundedAuditSink()
        self.controls = SystemNetworkControls(
            settings=SettingsControl(config=self.config, audit_sink=self.audit),
            blacklist=ContentBlacklistControl(config=self.config, registry=self.registry, audit_sink=self.audit),
            network=NetworkControl(
                gateway=self.gateway,
                operations=runtime.operations,
                audit_sink=self.audit,
                now=lambda: 1_767_326_400.0,
                ttl_seconds=60,
                start_worker=lambda worker: worker(),
            ),
        )


def build_p6_app(tmp_path: Path):
    app, runtime, _notifier = build_app(tmp_path)
    fixture = P6Fixture(runtime)
    app.dependency_overrides[get_bound_system_network_controls] = lambda: fixture.controls
    for domain_router in (settings_router, blacklist_router, network_router):
        app.include_router(domain_router, prefix="/api/management/v1")
    return app, runtime, fixture


__all__ = ["bearer", "build_p6_app", "create_session"]

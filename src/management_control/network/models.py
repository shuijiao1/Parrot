"""Typed transport-neutral DTOs for network management."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class DnsSettings:
    servers: tuple[str, ...]
    cacheTtlSeconds: int


@dataclass(frozen=True, slots=True)
class Socks5Settings:
    enabled: bool
    configured: bool
    maskedUrl: str | None


@dataclass(frozen=True, slots=True)
class ProxySummary:
    proxyCount: int
    groupCount: int
    ruleCount: int
    defaultRoute: str
    directFallback: bool


@dataclass(frozen=True, slots=True)
class NetworkSettings:
    dns: DnsSettings
    socks5: Socks5Settings
    proxySummary: ProxySummary
    revision: str


@dataclass(frozen=True, slots=True)
class NetworkTestPlan:
    id: str
    kind: str
    passed: bool
    tested: Any
    result: dict[str, Any]
    createdAt: datetime
    expiresAt: datetime
    revision: str


@dataclass(frozen=True, slots=True)
class DnsCacheEntry:
    host: str
    family: int
    servers: tuple[str, ...]
    ips: tuple[str, ...]
    expiresAt: datetime
    ttlRemainingSeconds: int


@dataclass(frozen=True, slots=True)
class DnsCachePage:
    items: tuple[DnsCacheEntry, ...]
    page: int
    pageSize: int
    total: int
    revision: str

    @property
    def hasNext(self) -> bool:
        return self.page * self.pageSize < self.total


@dataclass(frozen=True, slots=True)
class MonitorCoreSettings:
    openai: bool
    claude: bool
    cloudflare: bool


@dataclass(frozen=True, slots=True)
class MonitorChannelSettings:
    enabled: bool
    byChannel: dict[str, bool]


@dataclass(frozen=True, slots=True)
class NetworkMonitorSettings:
    enabled: bool
    intervalSeconds: int
    dns: bool
    socks5: bool
    core: MonitorCoreSettings
    channels: MonitorChannelSettings
    revision: str


@dataclass(frozen=True, slots=True)
class NetworkCheck:
    key: str
    label: str
    category: str
    ok: bool
    detail: str
    latencyMilliseconds: int | None
    checkedAt: datetime | None


@dataclass(frozen=True, slots=True)
class NetworkCheckPage:
    items: tuple[NetworkCheck, ...]
    page: int
    pageSize: int
    total: int
    revision: str

    @property
    def hasNext(self) -> bool:
        return self.page * self.pageSize < self.total

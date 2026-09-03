"""Strict camelCase schemas for P6 network management."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import ConfigDict, Field

from .base import ResponseMeta, StrictSchema


class StrictRequestSchema(StrictSchema):
    """P6 body base: OpenAPI JSON scalar types are never coerced."""

    model_config = ConfigDict(
        extra="forbid", populate_by_name=True, strict=True,
    )


class NetworkMonitorCategory(str, Enum):
    DNS = "dns"
    SOCKS5 = "socks5"
    CHANNEL = "channel"
    CORE = "core"


class DnsSettingsData(StrictSchema):
    servers: list[str]
    cacheTtlSeconds: int


class Socks5SettingsData(StrictSchema):
    enabled: bool
    configured: bool
    maskedUrl: str | None


class ProxySummaryData(StrictSchema):
    proxyCount: int
    groupCount: int
    ruleCount: int
    defaultRoute: str
    directFallback: bool


class NetworkSettingsData(StrictSchema):
    dns: DnsSettingsData
    socks5: Socks5SettingsData
    proxySummary: ProxySummaryData
    revision: str


class DnsTestRequest(StrictRequestSchema):
    servers: list[str] = Field(
        min_length=1,
        max_length=10,
        json_schema_extra={
            "writeOnly": True,
            "examples": [["https://dns.example/dns-query"]],
        },
    )


class Socks5TestRequest(StrictRequestSchema):
    url: str = Field(min_length=1, max_length=4096, json_schema_extra={"writeOnly": True})


class NetworkCommitRequest(StrictRequestSchema):
    planId: str = Field(min_length=1, max_length=128)
    force: bool = False


class Socks5StatePatch(StrictRequestSchema):
    enabled: bool


class DnsCacheEntryData(StrictSchema):
    host: str
    family: int
    servers: list[str]
    ips: list[str]
    expiresAt: datetime
    ttlRemainingSeconds: int


class DnsCacheListData(StrictSchema):
    items: list[DnsCacheEntryData]
    revision: str


class PageResponseMeta(ResponseMeta):
    page: int
    pageSize: int
    total: int
    hasNext: bool


class DnsCacheEnvelope(StrictSchema):
    data: DnsCacheListData
    meta: PageResponseMeta


class MonitorCoreData(StrictSchema):
    openai: bool
    claude: bool
    cloudflare: bool


class MonitorChannelsData(StrictSchema):
    enabled: bool
    byChannel: dict[str, bool]


class NetworkMonitorSettingsData(StrictSchema):
    enabled: bool
    intervalSeconds: int
    dns: bool
    socks5: bool
    core: MonitorCoreData
    channels: MonitorChannelsData
    revision: str


class MonitorCorePatch(StrictRequestSchema):
    openai: bool | None = None
    claude: bool | None = None
    cloudflare: bool | None = None


class MonitorChannelsPatch(StrictRequestSchema):
    enabled: bool | None = None
    byChannel: dict[str, bool] | None = None


class NetworkMonitorSettingsPatch(StrictRequestSchema):
    enabled: bool | None = None
    intervalSeconds: int | None = Field(default=None, ge=5)
    dns: bool | None = None
    socks5: bool | None = None
    core: MonitorCorePatch | None = None
    channels: MonitorChannelsPatch | None = None


class NetworkCheckData(StrictSchema):
    key: str
    label: str
    category: NetworkMonitorCategory
    ok: bool
    detail: str
    latencyMilliseconds: int | None
    checkedAt: datetime | None


class NetworkCheckListData(StrictSchema):
    items: list[NetworkCheckData]
    revision: str


class NetworkCheckEnvelope(StrictSchema):
    data: NetworkCheckListData
    meta: PageResponseMeta


class PageQuery(StrictSchema):
    page: int = Field(default=1, ge=1)
    pageSize: int = Field(default=50, ge=1, le=200)

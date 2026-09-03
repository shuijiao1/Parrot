"""Schemas for status-alert Management API operations."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .base import ResponseMeta, StrictSchema


StatusProvider = Literal["claude", "openai", "cloudflare"]
StatusImpact = Literal["none", "minor", "major", "critical"]


class StatusAlertSettingsData(StrictSchema):
    enabled: bool
    intervalSeconds: int
    targets: list[StatusProvider]
    minImpact: StatusImpact
    notificationEnabled: bool
    revision: str


class StatusAlertSettingsPatch(StrictSchema):
    enabled: bool = True
    intervalSeconds: int = Field(default=60, ge=10, le=86400)
    targets: list[StatusProvider] = Field(default_factory=list, max_length=3)
    minImpact: StatusImpact = "minor"


class StatusIncidentQuery(StrictSchema):
    view: Literal["active", "history", "muted"] = "active"
    provider: StatusProvider | None = None
    impact: Literal["none", "maintenance", "minor", "major", "critical"] | None = None
    sort: Literal["createdAtAsc", "createdAtDesc"] = "createdAtDesc"
    page: int = Field(default=1, ge=1)
    pageSize: int = Field(default=50, ge=1, le=200)


class StatusIncidentData(StrictSchema):
    id: str
    provider: StatusProvider
    name: str
    impact: str
    status: str
    createdAt: datetime | None
    updatedAt: datetime | None
    shortlink: str | None
    muted: bool
    active: bool
    mutedAt: datetime | None = None
    revision: str


class StatusIncidentListData(StrictSchema):
    items: list[StatusIncidentData]


class PageResponseMeta(ResponseMeta):
    page: int
    pageSize: int
    total: int
    hasNext: bool


class StatusIncidentListEnvelope(StrictSchema):
    data: StatusIncidentListData
    meta: PageResponseMeta

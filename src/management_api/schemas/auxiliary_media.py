"""Schemas for GPT image and xAI media settings operations."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from .base import StrictSchema


class ImageSettingsData(StrictSchema):
    enabled: bool
    cacheEnabled: bool
    mainModel: str
    toolModel: str
    cachePath: str
    cacheRetentionDays: int
    cacheMaxBytes: int
    revision: str


class ImageSettingsPatch(StrictSchema):
    enabled: bool = True
    cacheEnabled: bool = False
    mainModel: str = Field(default="gpt-5.4-mini", min_length=1, max_length=128)
    toolModel: str = Field(default="gpt-image-2", min_length=1, max_length=128)
    cachePath: str = Field(default="images", min_length=1, max_length=4096)
    cacheRetentionDays: int = Field(default=0, ge=0, le=36500)
    cacheMaxBytes: int = Field(default=1073741824, ge=0, le=2**63 - 1)


class ImageAccountStateData(StrictSchema):
    accountId: str
    email: str
    oauthEnabled: bool
    imageEnabled: bool
    imageCooldownUntil: datetime | None
    missingAccountId: bool
    revision: str


class ImageAccountStatePatch(StrictSchema):
    enabled: bool


class XaiMediaSettingsData(StrictSchema):
    imageModels: list[str]
    videoModels: list[str]
    jobTtlSeconds: int
    requestTimeoutSeconds: int
    revision: str


class XaiMediaSettingsPatch(StrictSchema):
    imageModels: list[str] = Field(default_factory=list, max_length=50)
    videoModels: list[str] = Field(default_factory=list, max_length=50)
    jobTtlSeconds: int = Field(default=10800, ge=1, le=2_147_483_647)
    requestTimeoutSeconds: int = Field(default=180, ge=1, le=2_147_483_647)

"""Strict OAuth settings, Telegram preference, and default-model schemas."""

from __future__ import annotations

from pydantic import Field

from src.management_control.oauth.models import CchMode, OAuthFamily, OAuthUsageDisplayMode

from .base import StrictSchema


class QuotaMonitorData(StrictSchema):
    enabled: bool
    intervalSeconds: int
    thresholdPercent: float


class OAuthSettingsData(StrictSchema):
    quotaMonitor: QuotaMonitorData
    cchMode: CchMode
    revision: str


class UpdateQuotaMonitorRequest(StrictSchema):
    enabled: bool | None = None
    intervalSeconds: int | None = Field(default=None, ge=10, le=86_400)
    thresholdPercent: float | None = Field(default=None, ge=1, le=100)


class UpdateOAuthSettingsRequest(StrictSchema):
    quotaMonitor: UpdateQuotaMonitorRequest | None = None
    cchMode: CchMode | None = None


class TelegramOAuthPreferencesData(StrictSchema):
    usageDisplayMode: OAuthUsageDisplayMode
    quotaProgressBar: bool
    revision: str


class UpdateTelegramOAuthPreferencesRequest(StrictSchema):
    usageDisplayMode: OAuthUsageDisplayMode | None = None
    quotaProgressBar: bool | None = None


class OAuthDefaultModelReferenceData(StrictSchema):
    kind: str
    owner: str
    modelId: str


class OAuthDefaultModelsData(StrictSchema):
    family: OAuthFamily
    models: list[str]
    references: list[OAuthDefaultModelReferenceData]
    revision: str


class ReplaceOAuthDefaultModelsRequest(StrictSchema):
    models: list[str] = Field(max_length=200)
    cleanupReferences: bool = False


class OAuthDefaultModelsResultData(StrictSchema):
    family: OAuthFamily
    models: list[str]
    cleanedApiKeys: list[str]
    skippedApiKeys: list[str]
    removedMappings: list[str]
    clearedDefaults: list[str]
    revision: str

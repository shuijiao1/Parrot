"""Public schemas for inventory, metadata bindings, catalog and sync."""

from __future__ import annotations

from enum import Enum

from pydantic import Field, ValidationInfo, field_validator, model_validator

from .base import ResponseMeta, StrictSchema
from .mapping import MappingListMeta
from .operations import ManagementOperationData


class InventorySort(str, Enum):
    MODEL_ID = "modelId"
    PROVIDER = "provider"
    CHANNEL_ID = "channelId"


class MetadataSort(str, Enum):
    MODEL_ID = "modelId"
    PROVIDER = "provider"
    SOURCE = "source"


class CatalogSort(str, Enum):
    NAME = "name"
    PROVIDER = "provider"
    MODEL_ID = "modelId"


class MetadataScope(str, Enum):
    GLOBAL = "global"
    OAUTH = "oauth"
    API = "api"


class MetadataSyncScope(str, Enum):
    FULL = "full"
    PROVIDER = "provider"
    ACCOUNT = "account"
    CHANNEL = "channel"


class ModelInventoryData(StrictSchema):
    modelId: str
    family: str
    provider: str
    channelId: str
    accountId: str | None
    outboundModel: str
    revision: str


class ModelInventoryListEnvelope(StrictSchema):
    data: list[ModelInventoryData]
    meta: MappingListMeta


class MetadataPricing(StrictSchema):
    input: float | None = None
    output: float | None = None
    cacheRead: float | None = None
    cacheWrite: float | None = None


class MetadataValues(StrictSchema):
    contextWindow: int | None = None
    contextWindowMaxMode: int | None = None
    maxOutputTokens: int | None = None
    compactTriggerTokens: int | None = None
    vision: bool | None = None
    reasoningEfforts: list[str] = Field(default_factory=list)
    defaultReasoningEffort: str | None = None
    inputModalities: list[str] = Field(default_factory=list)
    outputModalities: list[str] = Field(default_factory=list)
    cost: MetadataPricing | None = None


class ModelMetadataData(StrictSchema):
    modelId: str
    target: str | None
    providerId: str | None
    catalogModelId: str | None
    scope: MetadataScope
    scopeId: str | None
    outboundModel: str | None
    source: str
    authority: str
    effective: MetadataValues
    raw: MetadataValues
    revision: str


class ModelMetadataEnvelope(StrictSchema):
    data: ModelMetadataData
    meta: ResponseMeta


class ModelMetadataListEnvelope(StrictSchema):
    data: list[ModelMetadataData]
    meta: MappingListMeta


class PutMetadataBindingRequest(StrictSchema):
    scope: MetadataScope
    targetModelId: str = Field(min_length=3, max_length=500)
    providerId: str = Field(min_length=1, max_length=200)
    accountId: str | None = Field(default=None, min_length=1, max_length=500)
    channelId: str | None = Field(default=None, min_length=1, max_length=500)
    outboundModel: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("accountId", mode="before")
    @classmethod
    def reject_extra_account_selector(cls, value, info: ValidationInfo):
        scope = info.data.get("scope")
        if scope in {MetadataScope.GLOBAL, MetadataScope.API}:
            raise ValueError(f"{scope.value} scope does not accept accountId")
        return value

    @field_validator("channelId", mode="before")
    @classmethod
    def reject_extra_channel_selector(cls, value, info: ValidationInfo):
        scope = info.data.get("scope")
        if scope in {MetadataScope.GLOBAL, MetadataScope.OAUTH}:
            raise ValueError(f"{scope.value} scope does not accept channelId")
        return value

    @field_validator("outboundModel", mode="before")
    @classmethod
    def reject_global_outbound_selector(cls, value, info: ValidationInfo):
        if info.data.get("scope") is MetadataScope.GLOBAL:
            raise ValueError("global scope does not accept outboundModel")
        return value

    @model_validator(mode="after")
    def validate_scope_selector(self):
        if self.scope is MetadataScope.GLOBAL:
            if self.accountId is not None or self.channelId is not None or self.outboundModel is not None:
                raise ValueError("global scope does not accept scoped selectors")
        elif self.scope is MetadataScope.OAUTH:
            if not self.accountId or self.channelId is not None:
                raise ValueError("oauth scope requires only accountId")
            if not self.outboundModel:
                raise ValueError("oauth scope requires outboundModel")
        elif self.scope is MetadataScope.API:
            if not self.channelId or self.accountId is not None:
                raise ValueError("api scope requires only channelId")
            if not self.outboundModel:
                raise ValueError("api scope requires outboundModel")
        return self


class MetadataSyncRequest(StrictSchema):
    scope: MetadataSyncScope = MetadataSyncScope.FULL
    providerId: str | None = Field(default=None, min_length=1, max_length=200)
    accountId: str | None = Field(default=None, min_length=1, max_length=500)
    channelId: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def validate_selector(self):
        expected = {
            MetadataSyncScope.FULL: None,
            MetadataSyncScope.PROVIDER: "providerId",
            MetadataSyncScope.ACCOUNT: "accountId",
            MetadataSyncScope.CHANNEL: "channelId",
        }[self.scope]
        supplied = {
            "providerId": self.providerId,
            "accountId": self.accountId,
            "channelId": self.channelId,
        }
        if expected is None and any(supplied.values()):
            raise ValueError("full sync does not accept a selector")
        if expected is not None and not supplied[expected]:
            raise ValueError(f"{expected} is required for selected scope")
        if expected is not None and any(value for key, value in supplied.items() if key != expected):
            raise ValueError("only the selector matching scope is allowed")
        return self


class MetadataOperationEnvelope(StrictSchema):
    data: ManagementOperationData
    meta: ResponseMeta


class CatalogData(StrictSchema):
    key: str
    modelId: str
    name: str
    providerId: str
    providerName: str
    metadata: MetadataValues
    revision: str


class CatalogListEnvelope(StrictSchema):
    data: list[CatalogData]
    meta: MappingListMeta

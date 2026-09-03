"""Public schemas for load-balancing orders and affinity actions."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .base import ResponseMeta, StrictSchema


class LoadBalancingMode(str, Enum):
    SMART = "smart"
    ORDER = "order"
    PRIORITY = "priority"


class AffinityFamily(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


class LoadBalancingData(StrictSchema):
    mode: LoadBalancingMode
    revision: str


class LoadBalancingEnvelope(StrictSchema):
    data: LoadBalancingData
    meta: ResponseMeta


class UpdateLoadBalancingRequest(StrictSchema):
    mode: LoadBalancingMode


class OrderData(StrictSchema):
    modelId: str | None
    order: list[str]
    source: str
    revision: str


class OrderEnvelope(StrictSchema):
    data: OrderData
    meta: ResponseMeta


class ReplaceOrderRequest(StrictSchema):
    order: list[str] = Field(min_length=0, max_length=1000)


class BulkReplaceOrdersRequest(StrictSchema):
    modelIds: list[str] = Field(min_length=1, max_length=1000)
    order: list[str] = Field(min_length=0, max_length=1000)


class BulkOrderData(StrictSchema):
    orders: list[OrderData]
    revision: str


class BulkOrderEnvelope(StrictSchema):
    data: BulkOrderData
    meta: ResponseMeta


class AffinityClearData(StrictSchema):
    family: AffinityFamily | None
    fingerprintCount: int
    clientCount: int
    revision: str


class AffinityClearEnvelope(StrictSchema):
    data: AffinityClearData
    meta: ResponseMeta

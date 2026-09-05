"""Typed public schemas for management session grants and approvals."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, SecretStr, StringConstraints

from src.management_auth.principal import AuthMethod, Capability, Role

from .base import StrictSchema


SecretInput = Annotated[SecretStr, StringConstraints(min_length=1, max_length=4096)]


class ManagementKeyGrant(StrictSchema):
    grantType: Literal["managementKey"]
    managementKey: SecretInput = Field(
        json_schema_extra={"writeOnly": True, "examples": ["<write-only>"]}
    )


class TelegramApprovalGrant(StrictSchema):
    grantType: Literal["telegramApproval"]
    approvalId: Annotated[str, StringConstraints(min_length=8, max_length=128)]
    exchangeSecret: SecretInput = Field(
        json_schema_extra={"writeOnly": True, "examples": ["<write-only>"]}
    )


SessionGrant = Annotated[
    ManagementKeyGrant | TelegramApprovalGrant,
    Field(discriminator="grantType"),
]


class SessionSummary(StrictSchema):
    sessionId: str
    subjectId: str
    authMethod: AuthMethod
    roles: list[Role]
    capabilities: list[Capability]
    issuedAt: datetime
    expiresAt: datetime
    idleExpiresAt: datetime


class SessionCredentialData(StrictSchema):
    credential: str = Field(
        description="One-time session credential returned only by the exchange response",
        examples=["<one-time-credential>"],
    )
    session: SessionSummary


class TelegramApprovalCreateRequest(StrictSchema):
    clientName: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]
    deviceSummary: Annotated[
        str | None,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=160),
    ] = None


class TelegramApprovalCreatedData(StrictSchema):
    approvalId: str
    exchangeSecret: str = Field(
        description="One-time challenge secret returned only by the create response",
        examples=["<one-time-exchange-secret>"],
    )
    expiresAt: datetime
    pollAfterSeconds: int = Field(ge=1, le=30)


class TelegramApprovalStatusData(StrictSchema):
    approvalId: str
    status: Literal["pending", "approved", "denied", "expired", "consumed"]
    expiresAt: datetime
    pollAfterSeconds: int = Field(ge=1, le=30)

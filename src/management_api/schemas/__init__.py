"""Public Management API v1 schemas."""

from .auth import (
    ManagementKeyGrant,
    SessionCredentialData,
    SessionGrant,
    SessionSummary,
    TelegramApprovalCreateRequest,
    TelegramApprovalCreatedData,
    TelegramApprovalGrant,
    TelegramApprovalStatusData,
)
from .base import DataEnvelope, ErrorEnvelope, ResponseMeta
from .metadata import ManagementCapabilitiesData, ManagementMetadataData
from .operations import ManagementOperationData

__all__ = [
    "DataEnvelope",
    "ErrorEnvelope",
    "ManagementCapabilitiesData",
    "ManagementKeyGrant",
    "ManagementMetadataData",
    "ManagementOperationData",
    "ResponseMeta",
    "SessionCredentialData",
    "SessionGrant",
    "SessionSummary",
    "TelegramApprovalCreateRequest",
    "TelegramApprovalCreatedData",
    "TelegramApprovalGrant",
    "TelegramApprovalStatusData",
]

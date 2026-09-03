"""P0 auth, discovery and Operation routes for Management API v1."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response, status

from src.management_auth import (
    ApprovalError,
    AuthenticationRateLimited,
    Capability,
    SessionAuthenticationError,
)
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode
from src.management_control.operations import ManagementOperation

from ..dependencies import (
    AuthenticatedSession,
    ManagementRuntime,
    get_authenticated_session,
    get_management_context,
    get_management_runtime,
    management_request_id,
    require_capability,
)
from ..schemas import (
    DataEnvelope,
    ErrorEnvelope,
    ManagementCapabilitiesData,
    ManagementKeyGrant,
    ManagementMetadataData,
    ManagementOperationData,
    ResponseMeta,
    SessionCredentialData,
    SessionGrant,
    SessionSummary,
    TelegramApprovalCreateRequest,
    TelegramApprovalCreatedData,
    TelegramApprovalStatusData,
)
from ..schemas.metadata import CapabilityDomain, EnumDescriptor
from ..schemas.operations import OperationErrorData, OperationProgressData


router = APIRouter()
_ERROR_RESPONSES = {
    401: {"model": ErrorEnvelope, "description": "Management authentication failed"},
    403: {"model": ErrorEnvelope, "description": "Capability or Origin denied"},
    422: {"model": ErrorEnvelope, "description": "Typed request validation failed"},
    503: {"model": ErrorEnvelope, "description": "Management service is unavailable"},
}


def _meta(request: Request) -> ResponseMeta:
    return ResponseMeta(requestId=management_request_id(request))


def _session_summary(issued_or_verified) -> SessionSummary:
    principal = issued_or_verified.principal
    return SessionSummary(
        sessionId=principal.session_id or "",
        subjectId=principal.subject_id,
        authMethod=principal.auth_method,
        roles=sorted(principal.roles, key=lambda item: item.value),
        capabilities=sorted(principal.capabilities, key=lambda item: item.value),
        issuedAt=principal.issued_at,
        expiresAt=issued_or_verified.expires_at,
        idleExpiresAt=issued_or_verified.idle_expires_at,
    )


def _operation_data(operation: ManagementOperation) -> ManagementOperationData:
    progress = None
    if operation.progress is not None:
        progress = OperationProgressData(
            current=operation.progress.current,
            total=operation.progress.total,
            messageCode=operation.progress.message_code,
        )
    error = None
    if operation.error is not None:
        error = OperationErrorData(
            code=operation.error.code,
            message=operation.error.message,
            retryable=operation.error.retryable,
        )
    return ManagementOperationData(
        id=operation.id,
        kind=operation.kind,
        status=operation.status,
        progress=progress,
        createdAt=operation.created_at,
        startedAt=operation.started_at,
        finishedAt=operation.finished_at,
        result=operation.result,
        error=error,
        cancellable=operation.cancellable,
    )


@router.post(
    "/auth/sessions",
    operation_id="createManagementSession",
    tags=["management-auth"],
    status_code=status.HTTP_201_CREATED,
    response_model=DataEnvelope[SessionCredentialData],
    responses=_ERROR_RESPONSES,
)
async def create_management_session(
    grant: SessionGrant,
    request: Request,
    response: Response,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
) -> DataEnvelope[SessionCredentialData]:
    request_id = management_request_id(request)
    try:
        if isinstance(grant, ManagementKeyGrant):
            source = request.client.host if request.client else "unknown"
            issued = runtime.sessions.create_from_management_key(
                grant.managementKey.get_secret_value(),
                source=source,
                request_id=request_id,
            )
        else:
            issued = runtime.sessions.create_from_telegram_approval(
                approval_id=grant.approvalId,
                exchange_secret=grant.exchangeSecret.get_secret_value(),
                request_id=request_id,
            )
    except AuthenticationRateLimited as exc:
        raise ManagementError(
            ManagementErrorCode.RATE_LIMITED,
            retryable=True,
        ) from exc
    except SessionAuthenticationError as exc:
        raise ManagementError(ManagementErrorCode.AUTHENTICATION_FAILED) from exc
    response.headers["Cache-Control"] = "no-store"
    return DataEnvelope(
        data=SessionCredentialData(
            credential=issued.credential,
            session=_session_summary(issued),
        ),
        meta=_meta(request),
    )


@router.get(
    "/auth/session",
    operation_id="getCurrentManagementSession",
    tags=["management-auth"],
    response_model=DataEnvelope[SessionSummary],
    responses=_ERROR_RESPONSES,
)
async def get_current_management_session(
    request: Request,
    response: Response,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> DataEnvelope[SessionSummary]:
    response.headers["Cache-Control"] = "no-store"
    return DataEnvelope(data=_session_summary(authenticated.verified), meta=_meta(request))


@router.delete(
    "/auth/session",
    operation_id="revokeCurrentManagementSession",
    tags=["management-auth"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERROR_RESPONSES,
)
async def revoke_current_management_session(
    request: Request,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
) -> Response:
    runtime.sessions.revoke_current(
        authenticated.credential,
        request_id=management_request_id(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})


@router.post(
    "/auth/telegram-approvals",
    operation_id="createTelegramApproval",
    tags=["management-auth"],
    status_code=status.HTTP_201_CREATED,
    response_model=DataEnvelope[TelegramApprovalCreatedData],
    responses=_ERROR_RESPONSES,
)
async def create_telegram_approval(
    body: TelegramApprovalCreateRequest,
    request: Request,
    response: Response,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
) -> DataEnvelope[TelegramApprovalCreatedData]:
    request_id = management_request_id(request)
    try:
        issued = runtime.approvals.create(
            client_name=body.clientName,
            source_address=request.client.host if request.client else "unknown",
            device_summary=body.deviceSummary,
            request_id=request_id,
        )
    except AuthenticationRateLimited as exc:
        raise ManagementError(ManagementErrorCode.RATE_LIMITED, retryable=True) from exc
    except ApprovalError as exc:
        code = (
            ManagementErrorCode.RATE_LIMITED
            if exc.reason == "capacity"
            else ManagementErrorCode.DEPENDENCY_UNAVAILABLE
        )
        raise ManagementError(code, retryable=True) from exc
    response.headers["Cache-Control"] = "no-store"
    return DataEnvelope(
        data=TelegramApprovalCreatedData(
            approvalId=issued.approval_id,
            exchangeSecret=issued.exchange_secret,
            expiresAt=issued.expires_at,
            pollAfterSeconds=issued.poll_after_seconds,
        ),
        meta=_meta(request),
    )


@router.get(
    "/auth/telegram-approvals/{approvalId}",
    operation_id="getTelegramApproval",
    tags=["management-auth"],
    response_model=DataEnvelope[TelegramApprovalStatusData],
    responses=_ERROR_RESPONSES,
)
async def get_telegram_approval(
    approvalId: str,
    request: Request,
    response: Response,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
    authorization: Annotated[str | None, Header()] = None,
) -> DataEnvelope[TelegramApprovalStatusData]:
    if authorization is None or not authorization.startswith("Approval "):
        raise ManagementError(ManagementErrorCode.AUTHENTICATION_FAILED)
    exchange_secret = authorization[len("Approval ") :]
    try:
        view = runtime.approvals.get(approvalId, exchange_secret)
    except ApprovalError as exc:
        raise ManagementError(ManagementErrorCode.AUTHENTICATION_FAILED) from exc
    response.headers["Cache-Control"] = "no-store"
    return DataEnvelope(
        data=TelegramApprovalStatusData(
            approvalId=view.approval_id,
            status=view.status.value,
            expiresAt=view.expires_at,
            pollAfterSeconds=view.poll_after_seconds,
        ),
        meta=_meta(request),
    )


@router.get(
    "/meta",
    operation_id="getManagementMetadata",
    tags=["management-discovery"],
    response_model=DataEnvelope[ManagementMetadataData],
    responses=_ERROR_RESPONSES,
)
async def get_management_metadata(
    request: Request,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[ManagementMetadataData]:
    del context
    return DataEnvelope(
        data=ManagementMetadataData(
            apiVersion="v1",
            applicationVersion=runtime.application_version,
            supportedCapabilities=list(Capability),
            enums=[
                EnumDescriptor(name="authMethod", values=["managementKey", "telegramApproval"]),
                EnumDescriptor(
                    name="operationStatus",
                    values=["queued", "running", "succeeded", "failed", "cancelled"],
                ),
            ],
            documentationUrl=runtime.documentation_url,
        ),
        meta=_meta(request),
    )


@router.get(
    "/capabilities",
    operation_id="getManagementCapabilities",
    tags=["management-discovery"],
    response_model=DataEnvelope[ManagementCapabilitiesData],
    responses=_ERROR_RESPONSES,
)
async def get_management_capabilities(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[ManagementCapabilitiesData]:
    return DataEnvelope(
        data=ManagementCapabilitiesData(
            domains=[
                CapabilityDomain(
                    domain="management",
                    capabilities=sorted(context.actor.capabilities, key=lambda item: item.value),
                    actions=["session.revoke", "operation.get", "operation.cancel"],
                    providers=[],
                    presets=[],
                    protocols=[],
                    modes=[],
                )
            ]
        ),
        meta=_meta(request),
    )


@router.get(
    "/operations/{operationId}",
    operation_id="getManagementOperation",
    tags=["management-operations"],
    response_model=DataEnvelope[ManagementOperationData],
    responses=_ERROR_RESPONSES,
)
async def get_management_operation(
    operationId: str,
    request: Request,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
    context: Annotated[ManagementContext, Depends(get_management_context)],
) -> DataEnvelope[ManagementOperationData]:
    operation = runtime.operations.get(context, operationId)
    return DataEnvelope(data=_operation_data(operation), meta=_meta(request))


@router.delete(
    "/operations/{operationId}",
    operation_id="cancelManagementOperation",
    tags=["management-operations"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERROR_RESPONSES,
)
async def cancel_management_operation(
    operationId: str,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
    context: Annotated[ManagementContext, Depends(get_management_context)],
) -> Response:
    runtime.operations.cancel(context, operationId)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

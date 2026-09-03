"""FastAPI dependency boundary from Session credentials to control context."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Annotated, Callable

from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.management_auth import (
    ApprovalService,
    Capability,
    CapabilityDenied,
    ManagementStateStore,
    SessionAuthenticationError,
    SessionService,
    VerifiedSession,
    authorize,
)
from src.management_control import (
    ManagementContext,
    ManagementError,
    ManagementErrorCode,
    OperationRegistry,
    OperationStore,
    StoreAuditSink,
)


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_BEARER = HTTPBearer(auto_error=False, scheme_name="ManagementSession")


@dataclass(slots=True)
class ManagementRuntime:
    sessions: SessionService
    approvals: ApprovalService
    operations: OperationStore
    operation_registry: OperationRegistry
    audit_sink: StoreAuditSink
    state_store: ManagementStateStore
    allowed_origins: frozenset[str]
    application_version: str
    documentation_url: str

    def close(self) -> None:
        self.operations.interrupt_active()
        self.state_store.close()


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    credential: str
    verified: VerifiedSession


def management_request_id(request: Request) -> str:
    current = getattr(request.state, "management_request_id", None)
    if isinstance(current, str) and _REQUEST_ID_RE.fullmatch(current):
        return current
    supplied = request.headers.get("x-request-id", "")
    value = supplied if _REQUEST_ID_RE.fullmatch(supplied) else str(uuid.uuid4())
    request.state.management_request_id = value
    return value


def get_management_runtime(request: Request) -> ManagementRuntime:
    runtime = getattr(request.app.state, "management_runtime", None)
    if not isinstance(runtime, ManagementRuntime):
        raise ManagementError(
            ManagementErrorCode.SERVICE_NOT_READY,
            retryable=True,
        )
    return runtime


async def get_authenticated_session(
    request: Request,
    runtime: Annotated[ManagementRuntime, Depends(get_management_runtime)],
    authorization: Annotated[HTTPAuthorizationCredentials | None, Security(_BEARER)],
) -> AuthenticatedSession:
    if authorization is None or authorization.scheme.lower() != "bearer":
        raise ManagementError(ManagementErrorCode.SESSION_REQUIRED)
    try:
        verified = runtime.sessions.verify(authorization.credentials)
    except SessionAuthenticationError as exc:
        code = (
            ManagementErrorCode.SESSION_EXPIRED
            if exc.reason == "expired"
            else ManagementErrorCode.SESSION_REQUIRED
        )
        raise ManagementError(code) from exc
    return AuthenticatedSession(
        credential=authorization.credentials,
        verified=verified,
    )


async def get_management_context(
    request: Request,
    authenticated: Annotated[AuthenticatedSession, Depends(get_authenticated_session)],
) -> ManagementContext:
    idempotency = request.headers.get("idempotency-key")
    if idempotency is not None and not 1 <= len(idempotency) <= 128:
        raise ManagementError(ManagementErrorCode.INVALID_REQUEST)
    return ManagementContext(
        request_id=management_request_id(request),
        idempotency_key=idempotency,
        actor=authenticated.verified.principal,
    )


def require_capability(capability: Capability) -> Callable:
    async def dependency(
        context: Annotated[ManagementContext, Depends(get_management_context)],
    ) -> ManagementContext:
        try:
            authorize(context.actor, capability)
        except CapabilityDenied as exc:
            raise ManagementError(ManagementErrorCode.CAPABILITY_DENIED) from exc
        return context

    return dependency

"""FastAPI dependency boundary from Session credentials to control context."""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from threading import Event, RLock
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
from src.management_control.composition import ManagementControls, build_management_controls


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
    controls: ManagementControls | None = field(default=None, init=False, repr=False)
    _close_lock: RLock = field(default_factory=RLock, init=False, repr=False)
    _close_complete: Event = field(default_factory=Event, init=False, repr=False)
    _closing: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def control_owner(self) -> ManagementControls:
        """Return this runtime's one lazily-safe, lifecycle-bound Control graph."""
        with self._close_lock:
            if self._closed or self._closing:
                raise ManagementError(
                    ManagementErrorCode.SERVICE_NOT_READY,
                    retryable=True,
                )
            if self.controls is None:
                self.controls = build_management_controls(
                    audit_sink=self.audit_sink,
                    operations=self.operations,
                    operation_registry=self.operation_registry,
                )
            return self.controls

    def _claim_close(self) -> bool:
        with self._close_lock:
            if self._closed or self._closing:
                return False
            self._closing = True
            self.controls = None
            return True

    def _finish_close(self) -> None:
        try:
            self.state_store.close()
        finally:
            with self._close_lock:
                self._closed = True
                self._closing = False
                self._close_complete.set()

    def close(self) -> None:
        if not self._claim_close():
            self._close_complete.wait(5.1)
            return
        try:
            self.operations.close()
        finally:
            self._finish_close()

    async def aclose(self) -> None:
        if not self._claim_close():
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 5.1
            while not self._close_complete.is_set() and loop.time() < deadline:
                await asyncio.sleep(0.01)
            return
        try:
            await self.operations.aclose()
        finally:
            self._finish_close()


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


def get_management_control_owner(runtime: ManagementRuntime) -> ManagementControls:
    return runtime.control_owner()


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

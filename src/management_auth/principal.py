"""Management identity types shared by API and Telegram adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable


class AuthMethod(str, Enum):
    MANAGEMENT_KEY = "managementKey"
    TELEGRAM_APPROVAL = "telegramApproval"
    TELEGRAM_ADMIN = "telegramAdmin"


class Role(str, Enum):
    ADMINISTRATOR = "administrator"


class Capability(str, Enum):
    READ = "management.read"
    WRITE = "management.write"
    SECRETS_WRITE = "management.secrets.write"
    DESTRUCTIVE = "management.destructive"
    UPDATE = "management.update"
    LOG_BODY_READ = "management.logs.body.read"


ADMINISTRATOR_CAPABILITIES = frozenset(Capability)


@dataclass(frozen=True, slots=True)
class ManagementPrincipal:
    """An authenticated management actor, independent of its transport."""

    subject_id: str
    auth_method: AuthMethod
    roles: frozenset[Role]
    capabilities: frozenset[Capability]
    issued_at: datetime
    session_id: str | None = None

    def __post_init__(self) -> None:
        if not self.subject_id.strip():
            raise ValueError("subject_id must not be empty")
        if self.issued_at.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware")

    @classmethod
    def administrator(
        cls,
        *,
        subject_id: str,
        auth_method: AuthMethod,
        issued_at: datetime | None = None,
        session_id: str | None = None,
    ) -> "ManagementPrincipal":
        return cls(
            subject_id=subject_id,
            auth_method=auth_method,
            roles=frozenset({Role.ADMINISTRATOR}),
            capabilities=ADMINISTRATOR_CAPABILITIES,
            issued_at=issued_at or datetime.now(timezone.utc),
            session_id=session_id,
        )

    @classmethod
    def with_capabilities(
        cls,
        *,
        subject_id: str,
        auth_method: AuthMethod,
        capabilities: Iterable[Capability],
        issued_at: datetime,
        session_id: str | None = None,
    ) -> "ManagementPrincipal":
        return cls(
            subject_id=subject_id,
            auth_method=auth_method,
            roles=frozenset(),
            capabilities=frozenset(capabilities),
            issued_at=issued_at,
            session_id=session_id,
        )

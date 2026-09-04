"""Stable aggregation point for Management API domain routers."""

from __future__ import annotations

from threading import RLock
from typing import Iterable

from fastapi import APIRouter

from .routers import (
    apikey,
    channels,
    content_blacklist,
    load_balancing,
    logs,
    mapping,
    media,
    media_settings,
    model_metadata,
    network,
    oauth,
    overview,
    proxy,
    retention,
    stats,
    status,
    status_alerts,
    system_settings,
    translation,
    updates,
)
from .routers.foundation import router as foundation_router


_PREFIX = "/api/management/v1"
# Ordering is part of routing semantics: static retention routes must precede
# the logs router's dynamic /logs/{logId} routes.
_BUILTIN_DOMAIN_ROUTERS: tuple[APIRouter, ...] = (
    oauth.router,
    channels.router,
    apikey.router,
    overview.router,
    status.router,
    stats.router,
    retention.router,
    logs.router,
    media.router,
    mapping.router,
    model_metadata.router,
    load_balancing.router,
    proxy.router,
    translation.router,
    status_alerts.router,
    updates.router,
    media_settings.router,
    system_settings.router,
    content_blacklist.router,
    network.router,
)
_registered: list[APIRouter] = []
_lock = RLock()


def register_management_router(router: APIRouter) -> None:
    """Register one bounded extension router before the application is composed."""
    if not isinstance(router, APIRouter):
        raise TypeError("management domain router must be an APIRouter")
    with _lock:
        if any(existing is router for existing in _registered):
            raise ValueError("management domain router is already registered")
        _registered.append(router)


def create_management_router(
    extra_routers: Iterable[APIRouter] | None = None,
) -> APIRouter:
    """Compose the production router, or an explicit bounded subset for tests."""
    aggregate = APIRouter(prefix=_PREFIX)
    aggregate.include_router(foundation_router)
    selected = (
        _BUILTIN_DOMAIN_ROUTERS
        if extra_routers is None
        else tuple(extra_routers)
    )
    with _lock:
        registered = tuple(_registered)
    for domain_router in (*registered, *selected):
        aggregate.include_router(domain_router)
    return aggregate

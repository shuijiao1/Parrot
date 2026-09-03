"""Stable aggregation point for Management API domain routers."""

from __future__ import annotations

from threading import RLock
from typing import Iterable

from fastapi import APIRouter

from .routers.foundation import router as foundation_router


_PREFIX = "/api/management/v1"
_registered: list[APIRouter] = []
_lock = RLock()


def register_management_router(router: APIRouter) -> None:
    """Register one bounded domain router before the application is composed."""
    if not isinstance(router, APIRouter):
        raise TypeError("management domain router must be an APIRouter")
    with _lock:
        if any(existing is router for existing in _registered):
            raise ValueError("management domain router is already registered")
        _registered.append(router)


def create_management_router(extra_routers: Iterable[APIRouter] = ()) -> APIRouter:
    aggregate = APIRouter(prefix=_PREFIX)
    aggregate.include_router(foundation_router)
    with _lock:
        domain_routers = tuple(_registered)
    for domain_router in (*domain_routers, *tuple(extra_routers)):
        aggregate.include_router(domain_router)
    return aggregate

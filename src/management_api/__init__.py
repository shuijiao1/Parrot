"""Versioned Management API adapter public composition surface."""

from .dependencies import ManagementRuntime
from .error_mapping import (
    MANAGEMENT_ERROR_STATUS,
    install_management_error_handlers,
    management_error_responses,
)
from .origin import ManagementOriginMiddleware
from .router import (
    create_management_router,
    install_management_routers,
    register_management_router,
)

__all__ = [
    "MANAGEMENT_ERROR_STATUS",
    "ManagementOriginMiddleware",
    "ManagementRuntime",
    "create_management_router",
    "install_management_error_handlers",
    "install_management_routers",
    "management_error_responses",
    "register_management_router",
]

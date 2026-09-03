"""Versioned Management API adapter public composition surface."""

from .dependencies import ManagementRuntime
from .error_mapping import install_management_error_handlers
from .origin import ManagementOriginMiddleware
from .router import create_management_router, register_management_router

__all__ = [
    "ManagementOriginMiddleware",
    "ManagementRuntime",
    "create_management_router",
    "install_management_error_handlers",
    "register_management_router",
]

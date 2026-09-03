"""Proxy, proxy-group, probe and routing controls."""

from .control import (
    ProxyControl,
    ProxyGroupRecord,
    ProxyRecord,
    ProxyRoutingRecord,
    proxy_control,
)

__all__ = [
    "ProxyControl",
    "ProxyGroupRecord",
    "ProxyRecord",
    "ProxyRoutingRecord",
    "proxy_control",
]

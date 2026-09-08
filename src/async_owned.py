"""Wait for an owned transition before propagating caller cancellation."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

import anyio

_T = TypeVar("_T")


async def await_owned(awaitable: Awaitable[_T]) -> _T:
    """Keep the whole owner alive under asyncio and ASGI level cancellation.

    Shielding only the first wait is insufficient: after a disconnect AnyIO
    keeps cancelling at checkpoints, and explicit Task.cancel() may also repeat.
    Drain the same task, never restart its side effects, then propagate the
    original cancellation (or the owner's own failure, as for a normal await).
    """
    task = asyncio.ensure_future(awaitable)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            # Avoid a busy cancellation loop inside an already-cancelled AnyIO
            # scope. Explicit asyncio cancellations still need a shield per wait.
            with anyio.CancelScope(shield=True):
                while not task.done():
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        continue
                task.result()  # Also observe an owner failure/self-cancellation.
        finally:
            raise

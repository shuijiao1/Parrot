"""Small bounded daemon worker pool for management operation execution."""

from __future__ import annotations

from concurrent.futures import Future
from dataclasses import dataclass
from queue import Empty, Full, Queue
from threading import Lock, Thread, current_thread
from typing import Any, Callable


_STOP = object()


@dataclass(slots=True)
class _WorkItem:
    future: Future[Any]
    function: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]

    def run(self) -> None:
        if not self.future.set_running_or_notify_cancel():
            return
        try:
            result = self.function(*self.args, **self.kwargs)
        except BaseException as exc:
            self.future.set_exception(exc)
        else:
            self.future.set_result(result)


class DaemonBoundedExecutor:
    """A fixed-size daemon worker pool with a bounded submission queue.

    Running Python functions remain cooperative and cannot be force-stopped. The
    daemon workers ensure that a function still blocked after bounded runtime
    shutdown does not keep the interpreter alive.
    """

    def __init__(
        self,
        *,
        max_workers: int,
        max_queue_size: int,
        thread_name_prefix: str,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        if max_queue_size < 1:
            raise ValueError("max_queue_size must be positive")
        self._max_workers = max_workers
        self._thread_name_prefix = thread_name_prefix
        self._work_queue: Queue[_WorkItem | object] = Queue(maxsize=max_queue_size)
        self._state_lock = Lock()
        self._threads: list[Thread] = []
        self._shutdown = False

    def _start_workers(self) -> None:
        """Lazily start the complete fixed pool on its first submission."""
        if self._threads:
            return
        try:
            for index in range(self._max_workers):
                thread = Thread(
                    target=self._worker,
                    name=f"{self._thread_name_prefix}-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)
        except RuntimeError:
            # Partially started workers are daemon threads. Wake them and make
            # this executor permanently reject work rather than owning an
            # indeterminate pool size.
            self._shutdown = True
            if self._threads:
                self._work_queue.put_nowait(_STOP)
            raise

    def _worker(self) -> None:
        while True:
            item = self._work_queue.get()
            if item is _STOP:
                # One sentinel is sufficient for a bounded queue even when its
                # capacity is smaller than the worker count. Each exiting worker
                # hands it to the next worker (including workers that finish late).
                self._work_queue.put_nowait(_STOP)
                self._work_queue.task_done()
                return
            try:
                assert isinstance(item, _WorkItem)
                item.run()
            finally:
                self._work_queue.task_done()

    def submit(
        self,
        function: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> Future[Any]:
        if not callable(function):
            raise TypeError("function must be callable")
        with self._state_lock:
            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
            self._start_workers()
            future: Future[Any] = Future()
            try:
                self._work_queue.put_nowait(
                    _WorkItem(
                        future=future,
                        function=function,
                        args=args,
                        kwargs=kwargs,
                    )
                )
            except Full as exc:
                future.cancel()
                raise RuntimeError("bounded executor queue is full") from exc
            return future

    def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
        with self._state_lock:
            if not self._shutdown:
                self._shutdown = True
                if cancel_futures:
                    while True:
                        try:
                            item = self._work_queue.get_nowait()
                        except Empty:
                            break
                        try:
                            if isinstance(item, _WorkItem):
                                item.future.cancel()
                        finally:
                            self._work_queue.task_done()
                if self._threads:
                    self._work_queue.put_nowait(_STOP)
            threads = tuple(self._threads)

        if wait:
            caller = current_thread()
            for thread in threads:
                if thread is not caller:
                    thread.join()

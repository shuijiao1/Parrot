"""Third-reaudit gates for cancellation-log ownership and WS write ordering."""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest
from starlette.websockets import WebSocketState

from src import failover
from src.openai import responses_ws
from src.tests import conftest as test_conftest
from src.tests.reaudit2_runtime_cancellation_support import _StrictLogFakes, _schedule_result
from src.transports.timing import WsAttemptTiming


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "runtime",
    [failover, responses_ws],
    ids=["http-to-ws", "responses-ws"],
)
async def test_cancelled_ws_route_waits_for_open_worker_before_terminal(runtime, monkeypatch):
    """A cancelled caller cannot let its old open write trail the terminal write."""

    logs = _StrictLogFakes()
    loop = asyncio.get_running_loop()
    open_worker_entered = asyncio.Event()
    allow_open_worker = threading.Event()
    cancellation_seen = asyncio.Event()

    def update_proxy(*args, **kwargs):
        if kwargs.get("outcome") == "open":
            loop.call_soon_threadsafe(open_worker_entered.set)
            assert allow_open_worker.wait(timeout=5)
        logs.update_proxy_attempt(*args, **kwargs)

    monkeypatch.setattr(runtime.log_db, "update_proxy_attempt", update_proxy)
    monkeypatch.setattr(asyncio, "to_thread", test_conftest._ORIG_TO_THREAD)
    timing = WsAttemptTiming(route_type="direct", round_id="round-late-open")
    timing.mark_handshake_complete()
    proxy_bytes = runtime._WsProxyBytes(up=3, down=5)

    async def route_lifecycle():
        try:
            await runtime._persist_ws_route_round(
                "proxy-1",
                timing,
                proxy_bytes,
                outcome="open",
                terminal=False,
            )
        except asyncio.CancelledError:
            cancellation_seen.set()
            await runtime._persist_ws_route_round(
                "proxy-1",
                timing,
                proxy_bytes,
                outcome="cancelled",
                error_detail="cancelled",
                terminal=True,
            )
            raise

    task = asyncio.create_task(route_lifecycle())
    await open_worker_entered.wait()
    try:
        task.cancel()
        await asyncio.sleep(0)
        assert task.done() is False
        assert cancellation_seen.is_set() is False
        assert logs.proxy_updates == []

        allow_open_worker.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
    finally:
        allow_open_worker.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert cancellation_seen.is_set() is True
    assert [row["outcome"] for row in logs.proxy_updates] == ["open", "cancelled"]
    assert [row["proxy_attempt_id"] for row in logs.proxy_updates] == [
        "proxy-1", "proxy-1",
    ]
    assert logs.proxy_updates[0]["ended_at"] is None
    assert logs.proxy_updates[1]["ended_at"] is not None


@pytest.mark.asyncio
async def test_http_fast_mode_worker_cancellation_terminalizes_before_release(monkeypatch):
    logs = _StrictLogFakes()
    loop = asyncio.get_running_loop()
    worker_entered = asyncio.Event()
    allow_worker = threading.Event()
    release_calls: list[str] = []

    class Channel:
        key = "api:http-fast-cancel"
        type = "api"
        protocol = "openai-responses"
        provider = "openai"
        cc_mimicry = False
        upstream_stream_only = False

        async def build_upstream_request(self, body, resolved_model, *, ingress_protocol):
            del body, resolved_model, ingress_protocol
            return SimpleNamespace(
                body=b"{}",
                headers={},
                dynamic_tool_map=None,
                dispatch_metadata=None,
            )

    channel = Channel()

    def update_fast(*_args, **_kwargs):
        loop.call_soon_threadsafe(worker_entered.set)
        assert allow_worker.wait(timeout=5)

    monkeypatch.setattr(failover.log_db, "record_retry_attempt", logs.record_retry_attempt)
    monkeypatch.setattr(failover.log_db, "update_retry_attempt", logs.update_retry_attempt)
    monkeypatch.setattr(failover.log_db, "finish_error", logs.finish_error)
    monkeypatch.setattr(
        failover.log_db, "update_pending_fast_mode_from_upstream", update_fast,
    )
    monkeypatch.setattr(
        failover.config,
        "get",
        lambda: {
            "timeouts": {"connect": 1, "firstByte": 1, "idle": 1, "total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )
    monkeypatch.setattr(failover, "_pick_non_direct_proxy_name", lambda *_args: None)
    monkeypatch.setattr(
        failover,
        "_should_use_responses_upstream_ws",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(failover.concurrency, "try_acquire", lambda _key: _async_true())
    monkeypatch.setattr(failover.concurrency, "release", release_calls.append)
    monkeypatch.setattr(asyncio, "to_thread", test_conftest._ORIG_TO_THREAD)

    started_at = time.time()
    task = asyncio.create_task(failover.run_failover(
        _schedule_result(channel, queued=False),
        {"model": "m", "input": "hello", "stream": False},
        "request-http-fast-cancel",
        "key",
        "127.0.0.1",
        False,
        started_at,
        ingress_protocol="responses",
        start_monotonic=time.monotonic(),
    ))
    await worker_entered.wait()
    try:
        task.cancel()
        await asyncio.sleep(0)
        assert task.done() is False
        assert release_calls == []
        allow_worker.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
    finally:
        allow_worker.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert release_calls == [channel.key]
    assert [row["outcome"] for row in logs.retry_updates] == ["cancelled"]
    assert logs.retry_updates[0]["attempt_id"] == logs.retry_records[0]["handle"]
    assert logs.retry_updates[0]["ended_at"] is not None
    assert [
        (row["status"], row["http_status"]) for row in logs.request_terminals
    ] == [("cancelled", 499)]


async def _async_true() -> bool:
    return True


@pytest.mark.asyncio
async def test_http_to_ws_proxy_record_cancellation_terminalizes_all_once(monkeypatch):
    logs = _StrictLogFakes()
    loop = asyncio.get_running_loop()
    worker_entered = asyncio.Event()
    allow_worker = threading.Event()
    release_calls: list[str] = []

    class OAuthChannel:
        key = "oauth:http-to-ws-cancel"
        type = "oauth"
        protocol = "openai-responses"
        provider = "openai"
        cc_mimicry = False

    channel = OAuthChannel()

    def record_proxy(*args, **kwargs):
        loop.call_soon_threadsafe(worker_entered.set)
        assert allow_worker.wait(timeout=5)
        return logs.record_proxy_attempt(*args, **kwargs)

    async def build_request(*_args, **_kwargs):
        return "wss://unit.invalid", {}, "{}", None, failover.ConfuseState(), None

    monkeypatch.setattr(failover, "OpenAIOAuthChannel", OAuthChannel)
    monkeypatch.setattr(failover.log_db, "record_retry_attempt", logs.record_retry_attempt)
    monkeypatch.setattr(failover.log_db, "record_proxy_attempt", record_proxy)
    monkeypatch.setattr(failover.log_db, "update_proxy_attempt", logs.update_proxy_attempt)
    monkeypatch.setattr(failover.log_db, "update_retry_attempt", logs.update_retry_attempt)
    monkeypatch.setattr(failover.log_db, "finish_error", logs.finish_error)
    monkeypatch.setattr(failover, "_build_oauth_responses_ws_upstream_request", build_request)
    monkeypatch.setattr(
        failover, "_resolve_ws_route_chain_for_channel", lambda *_args: [("direct", None)],
    )
    monkeypatch.setattr(failover, "_pick_non_direct_proxy_name", lambda *_args: None)
    monkeypatch.setattr(
        failover,
        "_should_use_responses_upstream_ws",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        failover.config,
        "get",
        lambda: {
            "timeouts": {"connect": 1, "firstByte": 1, "idle": 1, "total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )
    monkeypatch.setattr(failover.concurrency, "try_acquire", lambda _key: _async_true())
    monkeypatch.setattr(failover.concurrency, "release", release_calls.append)
    monkeypatch.setattr(asyncio, "to_thread", test_conftest._ORIG_TO_THREAD)

    task = asyncio.create_task(failover.run_failover(
        _schedule_result(channel, queued=False),
        {"model": "m", "input": "hello", "stream": False},
        "request-http-to-ws-proxy-cancel",
        "key",
        "127.0.0.1",
        False,
        time.time(),
        ingress_protocol="responses",
        start_monotonic=time.monotonic(),
    ))
    await worker_entered.wait()
    try:
        task.cancel()
        await asyncio.sleep(0)
        assert task.done() is False
        assert release_calls == []
        allow_worker.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
    finally:
        allow_worker.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert release_calls == [channel.key]
    assert len(logs.retry_records) == 1
    assert len(logs.proxy_records) == 1
    assert [row["outcome"] for row in logs.proxy_updates] == ["cancelled"]
    assert logs.proxy_updates[0]["proxy_attempt_id"] == logs.proxy_records[0]["handle"]
    assert logs.proxy_updates[0]["ended_at"] is not None
    assert [row["outcome"] for row in logs.retry_updates] == ["cancelled"]
    assert logs.retry_updates[0]["attempt_id"] == logs.retry_records[0]["handle"]
    assert logs.retry_updates[0]["ended_at"] is not None
    assert [
        (row["status"], row["http_status"]) for row in logs.request_terminals
    ] == [("cancelled", 499)]


@pytest.mark.asyncio
async def test_responses_ws_proxy_record_cancellation_terminalizes_all_once(monkeypatch):
    logs = _StrictLogFakes()
    loop = asyncio.get_running_loop()
    worker_entered = asyncio.Event()
    allow_worker = threading.Event()
    release_calls: list[str] = []
    channel = SimpleNamespace(
        key="oauth:responses-ws-cancel",
        type="oauth",
        protocol="openai-responses",
        provider="openai",
    )

    def record_proxy(*args, **kwargs):
        loop.call_soon_threadsafe(worker_entered.set)
        assert allow_worker.wait(timeout=5)
        return logs.record_proxy_attempt(*args, **kwargs)

    async def build_request(*_args, **_kwargs):
        return SimpleNamespace(url="wss://unit.invalid", headers={}, translator_ctx=None)

    monkeypatch.setattr(responses_ws.log_db, "record_retry_attempt", logs.record_retry_attempt)
    monkeypatch.setattr(responses_ws.log_db, "record_proxy_attempt", record_proxy)
    monkeypatch.setattr(responses_ws.log_db, "update_proxy_attempt", logs.update_proxy_attempt)
    monkeypatch.setattr(responses_ws.log_db, "update_retry_attempt", logs.update_retry_attempt)
    monkeypatch.setattr(responses_ws.log_db, "finish_error", logs.finish_error)
    monkeypatch.setattr(responses_ws, "_build_ws_upstream_request", build_request)
    monkeypatch.setattr(
        responses_ws, "_resolve_ws_route_chain", lambda *_args: [("direct", None)],
    )
    monkeypatch.setattr(responses_ws, "_is_ws_capable_channel", lambda ch: ch is channel)
    monkeypatch.setattr(responses_ws, "_pick_non_direct_proxy_name", lambda *_args: None)
    monkeypatch.setattr(
        responses_ws.config,
        "get",
        lambda: {
            "timeouts": {"connect": 1, "firstByte": 1, "idle": 1, "total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )

    async def try_acquire(channel_key: str) -> bool:
        assert channel_key == channel.key
        return True

    monkeypatch.setattr(responses_ws.concurrency, "try_acquire", try_acquire)
    monkeypatch.setattr(responses_ws.concurrency, "release", release_calls.append)
    monkeypatch.setattr(asyncio, "to_thread", test_conftest._ORIG_TO_THREAD)

    task = asyncio.create_task(responses_ws._run_ws_failover(
        SimpleNamespace(application_state=WebSocketState.CONNECTED),
        first_obj={"type": "response.create", "model": "m", "input": []},
        schedule_result=_schedule_result(channel, queued=False),
        body={"model": "m", "input": [], "stream": True},
        request_id="request-responses-ws-proxy-cancel",
        api_key_name="key",
        client_ip="127.0.0.1",
        start_time=time.time(),
        start_monotonic=time.monotonic(),
        fp_query=None,
    ))
    await worker_entered.wait()
    try:
        task.cancel()
        await asyncio.sleep(0)
        assert task.done() is False
        assert release_calls == []
        allow_worker.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
    finally:
        allow_worker.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert release_calls == [channel.key]
    assert len(logs.retry_records) == 1
    assert len(logs.proxy_records) == 1
    assert [row["outcome"] for row in logs.proxy_updates] == ["cancelled"]
    assert logs.proxy_updates[0]["proxy_attempt_id"] == logs.proxy_records[0]["handle"]
    assert logs.proxy_updates[0]["ended_at"] is not None
    assert [row["outcome"] for row in logs.retry_updates] == ["cancelled"]
    assert logs.retry_updates[0]["attempt_id"] == logs.retry_records[0]["handle"]
    assert logs.retry_updates[0]["ended_at"] is not None
    assert [
        (row["status"], row["http_status"]) for row in logs.request_terminals
    ] == [("cancelled", 499)]


@pytest.mark.asyncio
async def test_responses_ws_finalized_child_is_not_terminalized_again(monkeypatch):
    """The route owner, not outer failover, emits the sole terminal update."""

    logs = _StrictLogFakes()
    release_calls: list[str] = []
    channel = SimpleNamespace(
        key="oauth:responses-ws-finalized",
        type="oauth",
        protocol="openai-responses",
        provider="openai",
    )

    monkeypatch.setattr(responses_ws.log_db, "record_retry_attempt", logs.record_retry_attempt)
    monkeypatch.setattr(responses_ws.log_db, "update_retry_attempt", logs.update_retry_attempt)
    monkeypatch.setattr(responses_ws.log_db, "finish_error", logs.finish_error)
    monkeypatch.setattr(responses_ws, "_is_ws_capable_channel", lambda ch: ch is channel)
    monkeypatch.setattr(responses_ws, "_pick_non_direct_proxy_name", lambda *_args: None)
    monkeypatch.setattr(
        responses_ws.config,
        "get",
        lambda: {
            "timeouts": {"connect": 1, "firstByte": 1, "idle": 1, "total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )

    async def try_acquire(channel_key: str) -> bool:
        assert channel_key == channel.key
        return True

    async def finalized_child(*_args, retry_attempt_id, **_kwargs):
        logs.update_retry_attempt(
            retry_attempt_id,
            ended_at=time.time(),
            outcome="client_disconnected",
            settle=False,
        )
        logs.finish_error(
            "request-responses-ws-finalized",
            "client disconnected",
            http_status=499,
            status="cancelled",
        )
        return responses_ws._WsAttemptResult(
            connected=True,
            closed_after_accept=True,
            outcome="client_disconnected",
            error_detail="client disconnected",
            request_finalized=True,
        )

    monkeypatch.setattr(responses_ws.concurrency, "try_acquire", try_acquire)
    monkeypatch.setattr(responses_ws.concurrency, "release", release_calls.append)
    monkeypatch.setattr(responses_ws, "_try_ws_channel", finalized_child)

    accepted = await responses_ws._run_ws_failover(
        SimpleNamespace(application_state=WebSocketState.CONNECTED),
        first_obj={"type": "response.create", "model": "m", "input": []},
        schedule_result=_schedule_result(channel, queued=False),
        body={"model": "m", "input": [], "stream": True},
        request_id="request-responses-ws-finalized",
        api_key_name="key",
        client_ip="127.0.0.1",
        start_time=time.time(),
        start_monotonic=time.monotonic(),
        fp_query=None,
    )

    assert accepted is True
    assert release_calls == [channel.key]
    assert [row["outcome"] for row in logs.retry_updates] == [
        "client_disconnected",
    ]
    assert logs.retry_updates[0]["attempt_id"] == logs.retry_records[0]["handle"]
    assert [
        (row["status"], row["http_status"]) for row in logs.request_terminals
    ] == [("cancelled", 499)]

"""Deterministic cancellation gates for P15 transport/stream ownership.

Every injected cancellation waits on an Event at the exact persistence await;
no timing sleep is used to discover the window. Log fakes intentionally mirror
production's explicit signatures so misspelled or surplus arguments fail fast.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.responses import StreamingResponse
from starlette.websockets import WebSocketState

from src import failover
from src.openai import responses_ws
from src.protocols.runtime import AttemptResult
from src.transports import http_runtime
from src.transports.http_runtime import HttpStreamStartResult, OpenedHttpResponse
from src.transports.timing import HttpAttemptTiming, RoundTimeouts


class _StrictLogFakes:
    def __init__(self) -> None:
        self.proxy_records: list[dict[str, Any]] = []
        self.proxy_updates: list[dict[str, Any]] = []
        self.retry_records: list[dict[str, Any]] = []
        self.retry_updates: list[dict[str, Any]] = []
        self.request_terminals: list[dict[str, Any]] = []
        self.pending_records: list[dict[str, Any]] = []

    def record_proxy_attempt(
        self,
        request_id,
        retry_attempt_id,
        attempt_order,
        proxy_name,
        started_at,
        *,
        round_id=None,
        transport=None,
        request_mode=None,
    ):
        handle = f"proxy-{len(self.proxy_records) + 1}"
        self.proxy_records.append({
            "handle": handle,
            "request_id": request_id,
            "retry_attempt_id": retry_attempt_id,
            "attempt_order": attempt_order,
            "proxy_name": proxy_name,
            "started_at": started_at,
            "round_id": round_id,
            "transport": transport,
            "request_mode": request_mode,
        })
        return handle

    def update_proxy_attempt(
        self,
        proxy_attempt_id,
        started_at=None,
        connect_ms=None,
        first_byte_ms=None,
        idle_ms=None,
        total_ms=None,
        dns_ms=None,
        tcp_ms=None,
        proxy_tcp_ms=None,
        proxy_tunnel_ms=None,
        tls_ms=None,
        target_tls_ms=None,
        ws_handshake_ms=None,
        request_upload_ms=None,
        response_headers_wait_ms=None,
        response_body_first_byte_wait_ms=None,
        ended_at=None,
        outcome=None,
        error_detail=None,
        bytes_up=None,
        bytes_down=None,
    ) -> None:
        self.proxy_updates.append({
            "proxy_attempt_id": proxy_attempt_id,
            "started_at": started_at,
            "connect_ms": connect_ms,
            "first_byte_ms": first_byte_ms,
            "idle_ms": idle_ms,
            "total_ms": total_ms,
            "dns_ms": dns_ms,
            "tcp_ms": tcp_ms,
            "proxy_tcp_ms": proxy_tcp_ms,
            "proxy_tunnel_ms": proxy_tunnel_ms,
            "tls_ms": tls_ms,
            "target_tls_ms": target_tls_ms,
            "ws_handshake_ms": ws_handshake_ms,
            "request_upload_ms": request_upload_ms,
            "response_headers_wait_ms": response_headers_wait_ms,
            "response_body_first_byte_wait_ms": response_body_first_byte_wait_ms,
            "ended_at": ended_at,
            "outcome": outcome,
            "error_detail": error_detail,
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
        })

    def record_retry_attempt(
        self,
        request_id,
        attempt_order,
        channel_key,
        channel_type,
        model,
        started_at,
        proxy_name=None,
        outbound_service_tier=None,
        upstream_protocol=None,
        client_visible_model=None,
    ):
        handle = f"retry-{len(self.retry_records) + 1}"
        self.retry_records.append({
            "handle": handle,
            "request_id": request_id,
            "attempt_order": attempt_order,
            "channel_key": channel_key,
            "channel_type": channel_type,
            "model": model,
            "started_at": started_at,
            "proxy_name": proxy_name,
            "outbound_service_tier": outbound_service_tier,
            "upstream_protocol": upstream_protocol,
            "client_visible_model": client_visible_model,
        })
        return handle

    def update_retry_attempt(
        self,
        attempt_id,
        final_round_id=None,
        connect_ms=None,
        first_byte_ms=None,
        idle_ms=None,
        attempt_elapsed_ms=None,
        request_upload_ms=None,
        response_headers_wait_ms=None,
        response_body_first_byte_wait_ms=None,
        total_ms=None,
        ended_at=None,
        outcome=None,
        error_detail=None,
        proxy_name=None,
        bytes_up=None,
        bytes_down=None,
        response_body=None,
        usage=None,
        usage_observed=None,
        settle=True,
    ) -> None:
        self.retry_updates.append({
            "attempt_id": attempt_id,
            "final_round_id": final_round_id,
            "connect_ms": connect_ms,
            "first_byte_ms": first_byte_ms,
            "idle_ms": idle_ms,
            "attempt_elapsed_ms": attempt_elapsed_ms,
            "request_upload_ms": request_upload_ms,
            "response_headers_wait_ms": response_headers_wait_ms,
            "response_body_first_byte_wait_ms": response_body_first_byte_wait_ms,
            "total_ms": total_ms,
            "ended_at": ended_at,
            "outcome": outcome,
            "error_detail": error_detail,
            "proxy_name": proxy_name,
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
            "response_body": response_body,
            "usage": usage,
            "usage_observed": usage_observed,
            "settle": settle,
        })

    def finish_error(
        self,
        request_id,
        error_message,
        retry_count=0,
        final_channel_key=None,
        final_channel_type=None,
        final_model=None,
        connect_ms=None,
        first_token_ms=None,
        idle_ms=None,
        total_ms=None,
        final_round_id=None,
        request_elapsed_ms=None,
        http_status=None,
        response_body=None,
        affinity_hit=0,
        upstream_protocol=None,
        upstream_transport=None,
        proxy_name=None,
        proxy_bytes_up=None,
        proxy_bytes_down=None,
        request_upload_ms=None,
        response_headers_wait_ms=None,
        response_body_first_byte_wait_ms=None,
        status="error",
        usage=None,
        usage_observed=None,
    ) -> None:
        self.request_terminals.append({
            "request_id": request_id,
            "error_message": error_message,
            "retry_count": retry_count,
            "final_channel_key": final_channel_key,
            "final_channel_type": final_channel_type,
            "final_model": final_model,
            "connect_ms": connect_ms,
            "first_token_ms": first_token_ms,
            "idle_ms": idle_ms,
            "total_ms": total_ms,
            "final_round_id": final_round_id,
            "request_elapsed_ms": request_elapsed_ms,
            "http_status": http_status,
            "response_body": response_body,
            "affinity_hit": affinity_hit,
            "upstream_protocol": upstream_protocol,
            "upstream_transport": upstream_transport,
            "proxy_name": proxy_name,
            "proxy_bytes_up": proxy_bytes_up,
            "proxy_bytes_down": proxy_bytes_down,
            "request_upload_ms": request_upload_ms,
            "response_headers_wait_ms": response_headers_wait_ms,
            "response_body_first_byte_wait_ms": response_body_first_byte_wait_ms,
            "status": status,
            "usage": usage,
            "usage_observed": usage_observed,
        })

    def insert_pending(
        self,
        request_id,
        client_ip,
        api_key_name,
        requested_model,
        is_stream,
        msg_count,
        tool_count,
        request_headers,
        request_body,
        fingerprint=None,
        ingress_protocol="anthropic",
        reasoning_effort=None,
        fast_mode=None,
        created_at=None,
    ) -> None:
        self.pending_records.append({
            "request_id": request_id,
            "client_ip": client_ip,
            "api_key_name": api_key_name,
            "requested_model": requested_model,
            "is_stream": is_stream,
            "msg_count": msg_count,
            "tool_count": tool_count,
            "request_headers": request_headers,
            "request_body": request_body,
            "fingerprint": fingerprint,
            "ingress_protocol": ingress_protocol,
            "reasoning_effort": reasoning_effort,
            "fast_mode": fast_mode,
            "created_at": created_at,
        })


class _CountingClient:
    def __init__(self) -> None:
        self.close_calls = 0

    async def aclose(self) -> None:
        self.close_calls += 1


class _Stats:
    def __init__(self) -> None:
        self.total_attempts = 0
        self.total_failures = 0
        self.total_successes = 0
        self.last_attempt_ts = 0.0
        self.last_success_ts = 0.0
        self.last_latency_ms = 0
        self.last_error = ""


class _Connector:
    type = "socks5"

    def __init__(self, client: _CountingClient) -> None:
        self.client = client
        self.stats = _Stats()

    def create_httpx_client(self, *, timeout, byte_counter, timing):
        self.timeout = timeout
        self.byte_counter = byte_counter
        self.timing = timing
        return self.client


class _CountingContext:
    def __init__(self) -> None:
        self.enter_calls = 0
        self.exit_calls = 0
        self.response = SimpleNamespace(status_code=200, headers={})

    async def __aenter__(self):
        self.enter_calls += 1
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        self.exit_calls += 1


class _Tracker:
    usage = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation": 0,
        "cache_read": 0,
    }
    usage_observed = False
    saw_stream_error = False
    saw_stream_end = False
    stream_error_message = None

    def get_full_response(self) -> str:
        return ""


class _HttpResponse:
    status_code = 200
    headers = {"content-type": "text/event-stream"}


class _NeverIterated:
    def __aiter__(self):
        return self

    async def __anext__(self):
        raise AssertionError("pending stream must be explicitly aborted, not iterated")


class _FakeLease:
    def __init__(self) -> None:
        self.release_calls = 0

    async def release(self) -> None:
        self.release_calls += 1


class _FakeDownstreamWebSocket:
    def __init__(self) -> None:
        self.headers = {}
        self.client = SimpleNamespace(host="127.0.0.1")
        self.application_state = WebSocketState.CONNECTING
        self.accept_calls = 0
        self.receive_calls = 0
        self.close_calls = 0

    async def accept(self) -> None:
        self.accept_calls += 1
        self.application_state = WebSocketState.CONNECTED

    async def receive(self) -> dict:
        self.receive_calls += 1
        assert self.receive_calls == 1
        return {
            "type": "websocket.receive",
            "text": '{"type":"response.create","model":"m","input":[]}',
        }

    async def close(self, code: int = 1000, reason: str = "") -> None:
        del code, reason
        self.close_calls += 1
        self.application_state = WebSocketState.DISCONNECTED


class _FakeUpstreamWebSocket:
    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


def _patch_http_logs(monkeypatch, logs: _StrictLogFakes) -> tuple[Any, Any]:
    record_proxy = logs.record_proxy_attempt
    update_proxy = logs.update_proxy_attempt
    monkeypatch.setattr(http_runtime.log_db, "record_proxy_attempt", record_proxy)
    monkeypatch.setattr(http_runtime.log_db, "update_proxy_attempt", update_proxy)
    monkeypatch.setattr(http_runtime.upstream, "get_client", lambda: object())
    return record_proxy, update_proxy


def _http_open_kwargs() -> dict[str, Any]:
    return {
        "channel": SimpleNamespace(),
        "resolved_model": "m",
        "upstream_req": SimpleNamespace(
            method="POST",
            url="https://unit.invalid",
            headers={},
            body=b"{}",
            dispatch_metadata=None,
        ),
        "connect_timeout": 1,
        "first_byte_timeout": 1,
        "idle_timeout": 1,
        "total_timeout": 5,
        "response_mode": "stream",
        "request_id": "request-1",
        "retry_attempt_id": "retry-1",
    }


@pytest.mark.asyncio
async def test_cancel_while_proxy_row_worker_waits_closes_owned_client_and_terminalizes_once(
    monkeypatch,
):
    logs = _StrictLogFakes()
    record_proxy, _update_proxy = _patch_http_logs(monkeypatch, logs)
    client = _CountingClient()
    connector = _Connector(client)
    monkeypatch.setattr(
        http_runtime,
        "_resolve_http_route_chain",
        lambda channel, resolved_model: ([('proxy-a', connector)], None),
    )

    worker_entered = asyncio.Event()
    allow_worker = asyncio.Event()

    async def controlled_to_thread(func, /, *args, **kwargs):
        if func is record_proxy:
            worker_entered.set()
            await allow_worker.wait()
        return func(*args, **kwargs)

    monkeypatch.setattr(http_runtime.asyncio, "to_thread", controlled_to_thread)
    task = asyncio.create_task(
        http_runtime.open_response_with_proxy_chain(**_http_open_kwargs())
    )
    await worker_entered.wait()
    task.cancel()
    allow_worker.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert client.close_calls == 1
    assert len(logs.proxy_records) == 1
    terminals = [row for row in logs.proxy_updates if row["outcome"] == "cancelled"]
    assert len(terminals) == 1
    assert terminals[0]["proxy_attempt_id"] == logs.proxy_records[0]["handle"]
    assert terminals[0]["ended_at"] is not None


@pytest.mark.asyncio
async def test_cancel_while_open_proxy_snapshot_waits_closes_ctx_and_client_once(
    monkeypatch,
):
    logs = _StrictLogFakes()
    _record_proxy, _update_proxy = _patch_http_logs(monkeypatch, logs)
    client = _CountingClient()
    connector = _Connector(client)
    context = _CountingContext()
    monkeypatch.setattr(
        http_runtime,
        "_resolve_http_route_chain",
        lambda channel, resolved_model: ([('proxy-a', connector)], None),
    )

    def open_stream(client_arg, request):
        assert client_arg is client
        del request
        return context

    monkeypatch.setattr(http_runtime, "open_stream", open_stream)
    open_worker_entered = asyncio.Event()
    allow_open_worker = asyncio.Event()

    async def controlled_to_thread(func, /, *args, **kwargs):
        if (
            func is http_runtime._persist_proxy_attempt_snapshot
            and kwargs.get("outcome") == "open"
        ):
            open_worker_entered.set()
            await allow_open_worker.wait()
        return func(*args, **kwargs)

    monkeypatch.setattr(http_runtime.asyncio, "to_thread", controlled_to_thread)
    task = asyncio.create_task(
        http_runtime.open_response_with_proxy_chain(**_http_open_kwargs())
    )
    await open_worker_entered.wait()
    task.cancel()
    allow_open_worker.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert context.enter_calls == 1
    assert context.exit_calls == 1
    assert client.close_calls == 1
    assert [row["outcome"] for row in logs.proxy_updates] == ["open", "cancelled"]
    assert sum(row["outcome"] == "cancelled" for row in logs.proxy_updates) == 1


def _schedule_result(ch, *, queued: bool):
    return SimpleNamespace(
        candidates=[] if queued else [(ch, "m")],
        saturated=[(ch, "m")] if queued else [],
        affinity_hit=False,
        fp_query=None,
        client_key=None,
        bound_channel_key=None,
        encrypted_content_count=0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("queued", [False, True], ids=["candidate", "queued"])
async def test_cancel_outer_retry_open_update_aborts_unstarted_http_stream_before_slot_release(
    monkeypatch,
    queued,
):
    logs = _StrictLogFakes()
    record_retry = logs.record_retry_attempt
    update_retry = logs.update_retry_attempt
    finish_error = logs.finish_error
    update_proxy = logs.update_proxy_attempt
    monkeypatch.setattr(failover.log_db, "record_retry_attempt", record_retry)
    monkeypatch.setattr(failover.log_db, "update_retry_attempt", update_retry)
    monkeypatch.setattr(failover.log_db, "finish_error", finish_error)
    monkeypatch.setattr(http_runtime.log_db, "update_proxy_attempt", update_proxy)
    monkeypatch.setattr(
        failover.config,
        "get",
        lambda: {
            "timeouts": {"connect": 1, "firstByte": 1, "idle": 1, "total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )
    monkeypatch.setattr(
        failover,
        "_pick_non_direct_proxy_name",
        lambda ch, resolved_model: None,
    )
    monkeypatch.setattr(
        failover,
        "_should_use_responses_upstream_ws",
        lambda ch, *, ingress_protocol, cfg=None: False,
    )

    channel = SimpleNamespace(
        key="api:one",
        type="api",
        protocol="anthropic",
        provider="anthropic",
        cc_mimicry=False,
        upstream_stream_only=False,
    )
    slot_releases: list[str] = []

    async def try_acquire(ch_key: str) -> bool:
        assert not queued
        assert ch_key == channel.key
        return True

    async def acquire_from_candidates(candidates, timeout: float):
        assert queued
        assert timeout == 1
        return candidates[0]

    def release(ch_key: str) -> None:
        slot_releases.append(ch_key)

    monkeypatch.setattr(failover.concurrency, "try_acquire", try_acquire)
    monkeypatch.setattr(
        failover.concurrency, "acquire_from_candidates", acquire_from_candidates,
    )
    monkeypatch.setattr(failover.concurrency, "release", release)

    context = _CountingContext()
    client = _CountingClient()
    timing = HttpAttemptTiming(response_mode="stream", round_id="round-1")
    timing.mark_connection_complete()
    timing.start_response_body_wait()
    timing.mark_response_body_byte(b"first")
    opened = OpenedHttpResponse(
        ctx=context,
        response=_HttpResponse(),
        connect_ms=timing.snapshot().connect_ms,
        timing=timing,
        proxy_name="proxy-a",
        proxy_bytes={"up": 3, "down": 4},
        proxy_client=client,
        proxy_attempt_id="proxy-1",
        round_timeouts=RoundTimeouts.from_config({
            "connect": 1, "firstByte": 1, "idle": 1, "total": 5,
        }),
    )

    async def prepare_stream_response_start(
        ctx,
        response,
        channel_arg,
        *,
        dynamic_map,
        connect_ms,
        deadline_ts,
        first_byte_timeout,
        idle_timeout,
        ingress_protocol,
        timing=None,
        round_timeouts=None,
        translator_ctx=None,
        partial_state=None,
    ):
        del (
            ctx, response, channel_arg, dynamic_map, connect_ms, deadline_ts,
            first_byte_timeout, idle_timeout, ingress_protocol, timing,
            round_timeouts, translator_ctx, partial_state,
        )
        return HttpStreamStartResult(
            aiter=_NeverIterated(),
            tracker=_Tracker(),
            builder=SimpleNamespace(),
            first_downstream_chunks=[b"first"],
            first_byte_ms=1,
            response_headers={},
            upstream_status=200,
        )

    monkeypatch.setattr(
        failover, "prepare_stream_response_start", prepare_stream_response_start,
    )

    async def try_channel(
        ch,
        resolved_model,
        body,
        is_stream,
        deadline_ts,
        start_time,
        fp_query,
        messages,
        api_key_name,
        client_ip,
        request_id,
        retry_count_so_far,
        affinity_hit,
        *,
        ingress_protocol="anthropic",
        client_key=None,
        retry_attempt_id=None,
        start_monotonic=None,
        attempt_start_monotonic=None,
        terminal_release=None,
    ):
        assert ch is channel
        assert is_stream is True
        return await failover._consume_stream(
            context,
            opened.response,
            ch,
            resolved_model,
            None,
            opened.connect_ms,
            start_time,
            deadline_ts,
            1,
            1,
            request_id,
            messages,
            api_key_name,
            client_ip,
            fp_query,
            retry_count_so_far,
            affinity_hit,
            ingress_protocol=ingress_protocol,
            translator_ctx=None,
            body=body,
            client_key=client_key,
            proxy_name=opened.proxy_name,
            proxy_bytes=opened.proxy_bytes,
            proxy_client=opened.proxy_client,
            timing=opened.timing,
            round_timeouts=opened.round_timeouts,
            opened_response=opened,
            retry_attempt_id=retry_attempt_id,
            start_monotonic=start_monotonic,
            attempt_start_monotonic=attempt_start_monotonic,
            cancel_state={},
            terminal_release=terminal_release,
        )

    monkeypatch.setattr(failover, "_try_channel", try_channel)

    retry_worker_entered = asyncio.Event()
    allow_retry_worker = asyncio.Event()

    async def controlled_to_thread(func, /, *args, **kwargs):
        if func is update_retry and kwargs.get("outcome") == "open":
            retry_worker_entered.set()
            await allow_retry_worker.wait()
        return func(*args, **kwargs)

    monkeypatch.setattr(failover.asyncio, "to_thread", controlled_to_thread)
    task = asyncio.create_task(failover.run_failover(
        _schedule_result(channel, queued=queued),
        {"model": "m", "stream": True, "messages": []},
        "request-1",
        "key-1",
        "127.0.0.1",
        True,
        time.time(),
        ingress_protocol="anthropic",
    ))
    await retry_worker_entered.wait()
    task.cancel()
    allow_retry_worker.set()

    with pytest.raises(asyncio.CancelledError):
        await task
    await http_runtime._drain_proxy_attempt_persistence()

    assert context.exit_calls == 1
    assert client.close_calls == 1
    assert slot_releases == [channel.key]
    assert sum(row["outcome"] == "open" for row in logs.retry_updates) == 1
    assert sum(
        row["outcome"] == "client_disconnected" for row in logs.retry_updates
    ) == 1
    assert len(logs.request_terminals) == 1
    assert logs.request_terminals[0]["status"] == "cancelled"
    assert logs.request_terminals[0]["http_status"] == 499
    assert sum(
        row["outcome"] == "client_disconnected" for row in logs.proxy_updates
    ) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("queued", [False, True], ids=["candidate", "queued"])
async def test_responses_ws_cancel_during_preaccept_retry_update_terminalizes_all_owners_once(
    monkeypatch,
    queued,
):
    logs = _StrictLogFakes()
    insert_pending = logs.insert_pending
    record_retry = logs.record_retry_attempt
    update_retry = logs.update_retry_attempt
    finish_error = logs.finish_error
    monkeypatch.setattr(responses_ws.log_db, "insert_pending", insert_pending)
    monkeypatch.setattr(responses_ws.log_db, "record_retry_attempt", record_retry)
    monkeypatch.setattr(responses_ws.log_db, "update_retry_attempt", update_retry)
    monkeypatch.setattr(responses_ws.log_db, "finish_error", finish_error)

    channel = SimpleNamespace(
        key="oauth:one",
        type="oauth",
        protocol="openai-responses",
        provider="openai",
        account_key="account-1",
        email="unit@example.invalid",
    )
    schedule = _schedule_result(channel, queued=queued)
    monkeypatch.setattr(
        responses_ws.auth,
        "validate",
        lambda headers: ("key-1", None, None),
    )
    monkeypatch.setattr(
        responses_ws,
        "_request_body_from_ws_create",
        lambda obj: {"model": obj["model"], "input": obj.get("input", [])},
    )
    monkeypatch.setattr(
        responses_ws.model_mapping,
        "apply_default",
        lambda body, ingress_protocol: None,
    )
    monkeypatch.setattr(
        responses_ws.model_mapping,
        "apply_mapping",
        lambda body, ingress_protocol: None,
    )
    monkeypatch.setattr(
        responses_ws,
        "guard_responses_ingress",
        lambda body, *, store_enabled: None,
    )
    monkeypatch.setattr(
        responses_ws.local_web_tools,
        "prepare_openai_responses_local_web_tools",
        lambda body: False,
    )
    monkeypatch.setattr(
        responses_ws.fingerprint,
        "fingerprint_query_responses",
        lambda api_key_name, client_ip, input_items: "fp-1",
    )

    def maybe_apply_auto_prompt_cache_key(
        body,
        *,
        fp_query,
        api_key_name="",
        client_ip="",
        model="",
        ingress_protocol="chat",
        claude_code_session_id=None,
        claude_code_agent_id=None,
    ):
        del (
            body, fp_query, api_key_name, client_ip, model, ingress_protocol,
            claude_code_session_id, claude_code_agent_id,
        )
        return None

    monkeypatch.setattr(
        responses_ws,
        "_maybe_apply_auto_prompt_cache_key",
        maybe_apply_auto_prompt_cache_key,
    )

    def schedule_request(
        body,
        api_key_name,
        client_ip,
        ingress_protocol="anthropic",
        fp_query=None,
    ):
        del body, api_key_name, client_ip, ingress_protocol, fp_query
        return schedule

    monkeypatch.setattr(responses_ws.scheduler, "schedule", schedule_request)

    async def translate_body(body, *, ingress_protocol, route=None):
        del ingress_protocol, route
        return body

    monkeypatch.setattr(responses_ws.translation, "translate_body", translate_body)

    lease = _FakeLease()

    async def acquire_api_key(key_name, request=None, *, receive=None):
        assert key_name == "key-1"
        assert request is None and receive is None
        return lease

    monkeypatch.setattr(responses_ws.apikey_limiter, "acquire", acquire_api_key)
    monkeypatch.setattr(
        responses_ws.config,
        "get",
        lambda: {
            "timeouts": {"total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )
    monkeypatch.setattr(
        responses_ws,
        "_is_ws_capable_channel",
        lambda ch: ch is channel,
    )
    monkeypatch.setattr(
        responses_ws,
        "_pick_non_direct_proxy_name",
        lambda ch, resolved_model: None,
    )

    slot_releases: list[str] = []

    async def try_acquire(ch_key: str) -> bool:
        assert not queued
        assert ch_key == channel.key
        return True

    async def acquire_from_candidates(candidates, timeout: float):
        assert queued
        assert timeout == 1
        return candidates[0]

    def release(ch_key: str) -> None:
        slot_releases.append(ch_key)

    monkeypatch.setattr(responses_ws.concurrency, "try_acquire", try_acquire)
    monkeypatch.setattr(
        responses_ws.concurrency, "acquire_from_candidates", acquire_from_candidates,
    )
    monkeypatch.setattr(responses_ws.concurrency, "release", release)

    upstream_ws = _FakeUpstreamWebSocket()

    async def try_ws_channel(
        websocket,
        *,
        first_obj,
        ch,
        resolved_model,
        body,
        allowed_models,
        deadline_ts,
        start_time,
        request_id,
        retry_count_so_far,
        affinity_hit,
        api_key_name,
        client_ip,
        fp_query,
        client_key,
        retry_attempt_id,
        start_monotonic,
        attempt_start_monotonic,
        turn_capacity,
    ):
        del (
            websocket, first_obj, resolved_model, body, allowed_models,
            deadline_ts, start_time, request_id, retry_count_so_far,
            affinity_hit, api_key_name, client_ip, fp_query, client_key,
            retry_attempt_id, start_monotonic, attempt_start_monotonic,
            turn_capacity,
        )
        assert ch is channel
        # Faithful pre-accept failure contract: the attempt closes its upstream
        # owner before returning a candidate-failover result.
        await upstream_ws.close()
        return responses_ws._WsAttemptResult(
            outcome="connect_error",
            error_detail="upstream rejected before accept",
            proxy_name="proxy-a",
            upstream_protocol="openai-responses",
            upstream_transport="ws",
        )

    monkeypatch.setattr(responses_ws, "_try_ws_channel", try_ws_channel)

    retry_worker_entered = asyncio.Event()
    allow_retry_worker = asyncio.Event()

    async def controlled_to_thread(func, /, *args, **kwargs):
        if func is update_retry:
            retry_worker_entered.set()
            await allow_retry_worker.wait()
        return func(*args, **kwargs)

    monkeypatch.setattr(responses_ws.asyncio, "to_thread", controlled_to_thread)
    websocket = _FakeDownstreamWebSocket()
    task = asyncio.create_task(responses_ws.handle_responses_ws(websocket))
    await retry_worker_entered.wait()
    task.cancel()
    allow_retry_worker.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert upstream_ws.close_calls == 1
    assert slot_releases == [channel.key]
    assert lease.release_calls == 1
    assert len(logs.retry_updates) == 1
    assert logs.retry_updates[0]["outcome"] == "connect_error"
    assert logs.retry_updates[0]["ended_at"] is not None
    assert len(logs.request_terminals) == 1
    assert logs.request_terminals[0]["status"] == "cancelled"
    assert logs.request_terminals[0]["http_status"] == 499


@pytest.mark.asyncio
async def test_cancel_outer_retry_update_aborts_unstarted_http_to_ws_stream(
    monkeypatch,
):
    logs = _StrictLogFakes()
    record_retry = logs.record_retry_attempt
    update_retry = logs.update_retry_attempt
    finish_error = logs.finish_error
    update_proxy = logs.update_proxy_attempt
    monkeypatch.setattr(failover.log_db, "record_retry_attempt", record_retry)
    monkeypatch.setattr(failover.log_db, "update_retry_attempt", update_retry)
    monkeypatch.setattr(failover.log_db, "finish_error", finish_error)
    monkeypatch.setattr(failover.log_db, "update_proxy_attempt", update_proxy)

    channel = SimpleNamespace(
        key="oauth:ws-one",
        type="oauth",
        protocol="openai-responses",
        provider="openai",
        cc_mimicry=False,
    )
    upstream_ws = _FakeUpstreamWebSocket()
    tracker = _Tracker()
    proxy_bytes = failover._WsProxyBytes(up=5, down=7)
    timing = failover.WsAttemptTiming(route_type="direct", round_id="ws-round-1")
    timing.mark_handshake_complete()
    timing.mark_ws_frame(b"first")
    round_timeouts = RoundTimeouts.from_config({
        "connect": 1, "firstByte": 1, "idle": 1, "total": 5,
    })

    async def recv_until_visible(
        upstream_ws_arg,
        tracker_arg,
        *,
        ch,
        deadline_ts,
        first_wait,
        idle_timeout,
        proxy_bytes,
        start_time,
        start_monotonic,
        timing,
        round_timeouts,
    ):
        del (
            deadline_ts, first_wait, idle_timeout, start_time, start_monotonic,
            timing, round_timeouts,
        )
        assert upstream_ws_arg is upstream_ws
        assert tracker_arg is tracker
        assert ch is channel
        assert proxy_bytes is not None
        return ['{"type":"response.output_text.delta","delta":"first"}'], None, 1

    monkeypatch.setattr(
        failover, "_recv_oauth_ws_until_visible", recv_until_visible,
    )
    started_at = time.time()
    started_monotonic = time.monotonic()
    stream_result = await failover._consume_oauth_responses_ws_stream(
        upstream_ws,
        tracker=tracker,
        ch=channel,
        resolved_model="m",
        deadline_ts=started_at + 5,
        start_time=started_at,
        start_monotonic=started_monotonic,
        connect_ms=1,
        first_byte_timeout=1,
        idle_timeout=1,
        request_id="request-ws-1",
        messages=[],
        api_key_name="key-1",
        client_ip="127.0.0.1",
        fp_query=None,
        retry_count_so_far=0,
        affinity_hit=0,
        translator_ctx=None,
        body={"model": "m", "stream": True},
        identity_state=failover.ConfuseState(),
        client_key=None,
        proxy_name="proxy-a",
        proxy_bytes=proxy_bytes,
        timing=timing,
        round_timeouts=round_timeouts,
        proxy_attempt_id="proxy-ws-1",
        retry_attempt_id="retry-1",
        attempt_start_monotonic=started_monotonic,
    )
    assert isinstance(stream_result.response, StreamingResponse)

    monkeypatch.setattr(
        failover.config,
        "get",
        lambda: {
            "timeouts": {"connect": 1, "firstByte": 1, "idle": 1, "total": 5},
            "concurrency": {"queueWaitSeconds": 1},
        },
    )
    monkeypatch.setattr(
        failover,
        "_pick_non_direct_proxy_name",
        lambda ch, resolved_model: None,
    )
    monkeypatch.setattr(
        failover,
        "_should_use_responses_upstream_ws",
        lambda ch, *, ingress_protocol, cfg=None: True,
    )
    slot_releases: list[str] = []

    async def try_acquire(ch_key: str) -> bool:
        assert ch_key == channel.key
        return True

    def release(ch_key: str) -> None:
        slot_releases.append(ch_key)

    monkeypatch.setattr(failover.concurrency, "try_acquire", try_acquire)
    monkeypatch.setattr(failover.concurrency, "release", release)

    async def try_responses_ws_channel(
        ch,
        resolved_model,
        body,
        is_stream,
        deadline_ts,
        start_time,
        fp_query,
        messages,
        api_key_name,
        client_ip,
        request_id,
        retry_count_so_far,
        affinity_hit,
        *,
        client_key=None,
        retry_attempt_id=None,
        start_monotonic=None,
        attempt_start_monotonic=None,
    ):
        del (
            resolved_model, body, deadline_ts, start_time, fp_query, messages,
            api_key_name, client_ip, request_id, retry_count_so_far,
            affinity_hit, client_key, retry_attempt_id, start_monotonic,
            attempt_start_monotonic,
        )
        assert ch is channel
        assert is_stream is True
        return stream_result

    monkeypatch.setattr(
        failover,
        "_try_openai_oauth_responses_ws_channel",
        try_responses_ws_channel,
    )

    retry_worker_entered = asyncio.Event()
    allow_retry_worker = asyncio.Event()

    async def controlled_to_thread(func, /, *args, **kwargs):
        if func is update_retry and kwargs.get("outcome") == "open":
            retry_worker_entered.set()
            await allow_retry_worker.wait()
        return func(*args, **kwargs)

    monkeypatch.setattr(failover.asyncio, "to_thread", controlled_to_thread)
    task = asyncio.create_task(failover.run_failover(
        _schedule_result(channel, queued=False),
        {"model": "m", "stream": True, "messages": []},
        "request-ws-1",
        "key-1",
        "127.0.0.1",
        True,
        started_at,
        ingress_protocol="responses",
        start_monotonic=started_monotonic,
    ))
    await retry_worker_entered.wait()
    task.cancel()
    allow_retry_worker.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert upstream_ws.close_calls == 1
    assert slot_releases == [channel.key]
    assert sum(row["outcome"] == "open" for row in logs.retry_updates) == 1
    assert sum(
        row["outcome"] == "client_disconnected" for row in logs.retry_updates
    ) == 1
    assert len(logs.request_terminals) == 1
    assert logs.request_terminals[0]["status"] == "cancelled"
    assert sum(
        row["outcome"] == "client_disconnected" for row in logs.proxy_updates
    ) == 1

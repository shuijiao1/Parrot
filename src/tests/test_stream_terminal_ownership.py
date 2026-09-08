"""Terminal frames and persistence must survive real ASGI/repeated cancellation."""
from __future__ import annotations

import asyncio
import json

import anyio
import httpx
import pytest

from src.tests import test_protocol_fake_upstreams as h
from src.tests import test_openai_responses_ws as w


def _import_modules():
    return {**h._import_modules(), **w._import_modules()}


def _configure(m, *, ws=False):
    h._setup(m)
    m["config"].update(lambda cfg: cfg.update({
        "apiKeys": ({"ws-key": {"key": "sk-ws", "allowedModels": []}}
                    if ws else h._default_key()),
        "network": {"routing": {"default": "direct"}},
        "timeouts": {"connect": 3, "firstByte": 3, "idle": 3, "total": 10},
        "concurrency": {"queueWaitSeconds": 1},
        "openai": {"responsesUpstreamWsForOAuth": False},
        "oauthAccounts": [], "channels": [],
    }))


def _snapshot(m):
    db = m["log_db"]._get_conn()
    row = dict(db.execute(
        "SELECT request_id,status,finished_at,http_status,final_channel_key "
        "FROM request_log ORDER BY id DESC LIMIT 1"
    ).fetchone())
    row["attempts"] = [dict(r) for r in db.execute(
        "SELECT outcome,ended_at FROM retry_chain WHERE request_id=? ORDER BY id",
        (row["request_id"],),
    )]
    return row


def _events(error=False, terminal_only=False):
    events = [{"type": "response.created", "response": {"id": "terminal-owned"}}]
    if not terminal_only:
        events.append({"type": "response.output_text.delta", "output_index": 0,
                       "content_index": 0, "delta": "OK"})
    response = {"id": "terminal-owned", "status": "failed" if error else "completed",
                "output": [], "usage": {"input_tokens": 8, "output_tokens": 3}}
    if error:
        response["error"] = {"code": "server_error", "message": "terminal upstream failure"}
    events.append({"type": "response.failed" if error else "response.completed",
                   "response": response})
    return events


def _payload(protocol, error):
    if protocol == "chat":
        body = h._chat_sse_response("OK").content
        if error:
            body = body.split(b'data: {"id":"chatcmpl_sse","object":"chat.completion.chunk","created":1,"model":"gpt-real","choices":[{"index":0,"delta":{},')[0]
            body += b'data: {"error":{"type":"server_error","message":"terminal upstream failure"}}\n\n'
        return body, (b"terminal upstream failure" if error else b"[DONE]")
    if protocol == "anthropic":
        body = h._anthropic_sse_response("OK").content
        if error:
            body = body.split(b"event: message_delta")[0]
            body += b'event: error\ndata: {"type":"error","error":{"type":"api_error","message":"terminal upstream failure"}}\n\n'
        return body, (b"terminal upstream failure" if error else b"event: message_stop")
    return b"".join(h._responses_sse_event(e["type"], e) for e in _events(error)), (
        b"response.failed" if error else b"response.completed"
    )


async def _http_response(m, monkeypatch, protocol, *, error=False, batch=False):
    _configure(m)
    router = h.MockRouter()
    if protocol == "oauth_ws":
        ch = h._make_openai_oauth_channel("terminal-owned@example.invalid")
        m["config"].update(lambda cfg: cfg.update({
            "openai": {"responsesUpstreamWsForOAuth": True},
            "oauthAccounts": [{"email": "terminal-owned@example.invalid", "provider": "openai",
                "workspace_id": "ws-terminal-owned@example.invalid",
                "chatgpt_account_id": "ws-terminal-owned@example.invalid",
                "accessToken": "fake", "refreshToken": "fake", "models": ["gpt-5"],
                "account_model_catalog": {"schema": 1, "models": [{"id": "gpt-5", "useResponsesLite": False}]},
                "codexIdentity": ch.codex_account_identity.as_config(),
                "codexDeviceInstallationId": ch.codex_device_installation_id}],
        }))
        upstream = h.FakeOAuthResponseWs(_events(error, terminal_only=batch))
        async def fake_token(*args, **kwargs):
            return "fake"
        async def fake_connect(*args, **kwargs):
            return upstream
        monkeypatch.setattr(m["failover"].oauth_manager, "ensure_valid_token", fake_token)
        monkeypatch.setattr(m["failover"], "_connect_oauth_responses_ws", fake_connect)
        h._install_channels(m, [ch])
        resp, client = await h._call_openai_handler(m, router, "responses", {
            "model": "gpt-5", "stream": True, "input": "Only reply OK",
        })
        terminal = b"response.failed" if error else b"response.completed"
        return resp, client, terminal
    base = "https://terminal-owned.example"
    payload, terminal = _payload(protocol, error)
    chunks = [payload] if batch else [part + b"\n\n" for part in payload.split(b"\n\n") if part]
    router.register(base, lambda req: httpx.Response(
        200, stream=h.ChunkedByteStream(chunks), headers={"content-type": "text/event-stream"},
    ))
    if protocol == "anthropic":
        ch = h._make_anthropic_channel(m, "terminal-owned", base, alias="test-model", real="claude-real")
        h._install_channels(m, [ch])
        resp, client, _ = await h._call_anthropic_core(m, router, {
            "model": "test-model", "stream": True, "max_tokens": 32,
            "messages": [{"role": "user", "content": "Only reply OK"}],
        })
    else:
        ch = h._make_openai_channel("terminal-owned", base,
            protocol="openai-chat" if protocol == "chat" else "openai-responses",
            alias="test-model", real="gpt-real")
        h._install_channels(m, [ch])
        body = {"model": "test-model", "stream": True}
        body.update({"messages": [{"role": "user", "content": "Only reply OK"}]}
                    if protocol == "chat" else {"input": "Only reply OK"})
        resp, client = await h._call_openai_handler(m, router, protocol, body)
    return resp, client, terminal


@pytest.mark.parametrize("protocol", ["chat", "anthropic", "responses", "oauth_ws"])
@pytest.mark.parametrize("error", [False, True], ids=["success", "error"])
@pytest.mark.parametrize("batch", [False, True], ids=["later-terminal", "first-batch-terminal"])
async def test_http_terminal_is_logged_before_exposing_frame(m, monkeypatch, protocol, error, batch):
    resp, client, terminal = await _http_response(m, monkeypatch, protocol, error=error, batch=batch)
    try:
        assert resp.status_code == 200
        emitted = b""
        for _ in range(30):
            chunk = await asyncio.wait_for(anext(resp.body_iterator), 2)
            emitted += chunk.encode() if isinstance(chunk, str) else chunk
            if terminal in emitted:
                break
        assert terminal in emitted
        row = _snapshot(m)
        assert row["status"] == ("error" if error else "success"), row
        assert row["finished_at"] is not None
        assert row["attempts"][0]["outcome"] != "open"
    finally:
        await resp.body_iterator.aclose()
        await client.aclose()


@pytest.mark.parametrize("protocol", ["chat", "anthropic", "responses", "oauth_ws"])
@pytest.mark.parametrize("mode", ["full_read", "single_cancel", "asgi_disconnect"])
async def test_http_terminal_db_sequence_survives_cancellation(m, monkeypatch, protocol, mode):
    resp, client, _ = await _http_response(m, monkeypatch, protocol)
    entered, release = asyncio.Event(), asyncio.Event()
    original = asyncio.to_thread
    finished = []
    async def controlled(func, /, *args, **kwargs):
        if func is m["log_db"].finish_success:
            finished.append(args[0])
        result = await original(func, *args, **kwargs)
        if func is m["log_db"].update_retry_attempt and kwargs.get("outcome") == "success":
            entered.set()
            await release.wait()
        return result
    monkeypatch.setattr(asyncio, "to_thread", controlled)
    async def receive():
        await entered.wait()
        return {"type": "http.disconnect"}
    async def send(message):
        pass
    coro = (resp({"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}}, receive, send)
            if mode == "asgi_disconnect" else h._consume_streaming_to_string(resp))
    consumer = asyncio.create_task(coro)
    try:
        await asyncio.wait_for(entered.wait(), 2)
        if mode == "single_cancel":
            consumer.cancel()
        for _ in range(20):
            await asyncio.sleep(0)
        release.set()
        try:
            await asyncio.wait_for(consumer, 2)
        except asyncio.CancelledError:
            assert mode == "single_cancel"
        row = _snapshot(m)
        assert row["status"] == "success", row
        assert len(finished) == 1
    finally:
        release.set()
        if not consumer.done():
            consumer.cancel()
            await asyncio.gather(consumer, return_exceptions=True)
        await resp.body_iterator.aclose()
        await client.aclose()


@pytest.mark.parametrize("owner", ["ws", "http", "managed_ws", "ss2022", "tls_ss2022"])
@pytest.mark.parametrize("mode", ["single", "repeated", "anyio"])
async def test_transport_owner_waits_for_cleanup_despite_cancellation(owner, mode):
    from src.transports.ws_runtime import await_ws_owned, ManagedWsConnection
    from src.transports.http_runtime import _await_http_owned
    from src.proxy.connector import SS2022DuplexBridge, _TLSOverSS2022Stream
    entered, release = asyncio.Event(), asyncio.Event()
    effects = []
    async def owned():
        entered.set()
        await release.wait()
        effects.append("finished")
    operation = asyncio.create_task(owned())
    if owner == "ws":
        waiter = lambda: await_ws_owned(operation)
    elif owner == "http":
        waiter = lambda: _await_http_owned(operation)
    elif owner == "ss2022":
        obj = object.__new__(SS2022DuplexBridge)
        waiter = lambda: obj._await_close_task(operation)
    else:
        cls = ManagedWsConnection if owner == "managed_ws" else _TLSOverSS2022Stream
        obj = object.__new__(cls)
        obj._close_task = operation
        waiter = obj.close if owner == "managed_ws" else obj.aclose
    scope_ready = asyncio.Event()
    scopes = []
    async def scoped():
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            scope_ready.set()
            await waiter()
    consumer = asyncio.create_task(scoped() if mode == "anyio" else waiter())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        if mode == "anyio":
            await scope_ready.wait()
            scopes[0].cancel()
        else:
            consumer.cancel()
        for _ in range(10):
            await asyncio.sleep(0)
        if mode == "repeated":
            consumer.cancel()
            for _ in range(10):
                await asyncio.sleep(0)
        assert not operation.cancelled()
        assert not consumer.done()
        release.set()
        try:
            await asyncio.wait_for(consumer, 2)
        except asyncio.CancelledError:
            assert mode != "anyio"
        assert effects == ["finished"]
    finally:
        release.set()
        await asyncio.gather(operation, consumer, return_exceptions=True)


async def _ws_call(m, monkeypatch, transport, *, error=False, terminal_only=False, on_terminal=None):
    _configure(m, ws=True)
    base = "https://ws-terminal-owned.example"
    h._install_channels(m, [h._make_openai_channel(
        "ws-terminal-owned", base, protocol="openai-responses",
        alias="test-model", real="gpt-real", extra={"responsesWsUpstreamTransport": transport},
    )])
    class Client(w.FakeWebSocket):
        async def send_text(self, text):
            if json.loads(text).get("type") in {"response.completed", "response.failed"}:
                if on_terminal is not None:
                    on_terminal()
            await super().send_text(text)
    ws = Client({"type": "response.create", "model": "test-model", "input": "OK", "stream": True})
    events = _events(error, terminal_only)
    client = None
    if transport == "ws":
        upstream = w.FakeUpstreamWebSocket(events)
        async def connect(*args, **kwargs):
            return upstream
        monkeypatch.setattr(m["responses_ws"], "_connect_upstream_ws", connect)
    else:
        router = h.MockRouter()
        payload = b"".join(h._responses_sse_event(e["type"], e) for e in events)
        router.register(base, lambda req: httpx.Response(
            200, stream=h.ChunkedByteStream([payload]), headers={"content-type": "text/event-stream"},
        ))
        client = httpx.AsyncClient(transport=httpx.MockTransport(router.handle))
        m["upstream"].set_client(client)
    return ws, client


@pytest.mark.parametrize("transport", ["ws", "sse"])
@pytest.mark.parametrize("error", [False, True], ids=["success", "error"])
@pytest.mark.parametrize("terminal_only", [False, True], ids=["after-delta", "terminal-only"])
async def test_ws_terminal_is_logged_before_send(m, monkeypatch, transport, error, terminal_only):
    at_terminal = []
    ws, client = await _ws_call(m, monkeypatch, transport, error=error, terminal_only=terminal_only,
        on_terminal=lambda: at_terminal.append(_snapshot(m)))
    try:
        await asyncio.wait_for(m["responses_ws"].handle_responses_ws(ws), 3)
        assert len(at_terminal) == 1
        assert at_terminal[0]["status"] == ("error" if error else "success"), at_terminal
        assert at_terminal[0]["finished_at"] is not None
        assert _snapshot(m)["status"] == ("error" if error else "success")
    finally:
        if client:
            await client.aclose()


@pytest.mark.parametrize("mode", ["value", "error", "self_cancel"])
async def test_owned_wait_preserves_own_result_and_self_cancellation(mode):
    from src.async_owned import await_owned
    async def operation():
        if mode == "error":
            raise ValueError("owned failure")
        if mode == "self_cancel":
            raise asyncio.CancelledError()
        return 42
    if mode == "error":
        with pytest.raises(ValueError, match="owned failure"):
            await asyncio.wait_for(await_owned(operation()), 1)
    elif mode == "self_cancel":
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(await_owned(operation()), 1)
    else:
        assert await asyncio.wait_for(await_owned(operation()), 1) == 42


@pytest.mark.parametrize("transport", ["ws", "sse"])
@pytest.mark.parametrize("error", [False, True], ids=["success", "error"])
@pytest.mark.parametrize("terminal_only", [False, True], ids=["after-delta", "terminal-only"])
async def test_ws_disconnect_at_terminal_preserves_finished_log(m, monkeypatch, transport, error, terminal_only):
    from starlette.websockets import WebSocketDisconnect, WebSocketState
    def disconnected():
        # A real disconnected socket also wakes receive(), rather than leaving
        # the synthetic persistent client's next-turn wait blocked forever.
        ws._closed.set()
        ws.application_state = WebSocketState.DISCONNECTED
        raise WebSocketDisconnect(code=1000)
    ws, client = await _ws_call(m, monkeypatch, transport, error=error, terminal_only=terminal_only,
        on_terminal=disconnected)
    try:
        await asyncio.wait_for(m["responses_ws"].handle_responses_ws(ws), 3)
        row = _snapshot(m)
        assert row["status"] == ("error" if error else "success"), row
        assert row["attempts"][0]["outcome"] == ("stream_upstream_error" if error else "success"), row
    finally:
        if client:
            await client.aclose()


@pytest.mark.parametrize("transport", ["ws", "sse"])
async def test_ws_terminal_db_sequence_survives_repeated_cancel(m, monkeypatch, transport):
    ws, client = await _ws_call(m, monkeypatch, transport)
    entered, release = asyncio.Event(), asyncio.Event()
    original = asyncio.to_thread
    finishes = []
    async def controlled(func, /, *args, **kwargs):
        if func is m["log_db"].finish_success:
            finishes.append(args[0])
        result = await original(func, *args, **kwargs)
        if func is m["log_db"].update_retry_attempt and kwargs.get("outcome") == "success":
            entered.set()
            await release.wait()
        return result
    monkeypatch.setattr(asyncio, "to_thread", controlled)
    consumer = asyncio.create_task(m["responses_ws"].handle_responses_ws(ws))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        consumer.cancel()
        for _ in range(10):
            await asyncio.sleep(0)
        consumer.cancel()
        for _ in range(10):
            await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(consumer, 2)
        row = _snapshot(m)
        assert row["status"] == "success", row
        assert len(finishes) == 1
        assert row["attempts"][0]["outcome"] == "success", row
    finally:
        release.set()
        await asyncio.gather(consumer, return_exceptions=True)
        if client:
            await client.aclose()

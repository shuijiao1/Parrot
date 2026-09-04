"""Split P15 cancellation ownership gates; shared fakes live in the support module."""

from src.tests.reaudit2_runtime_cancellation_support import *  # noqa: F401,F403

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

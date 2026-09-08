"""Offline diagnostics only: retain evidence without changing WS/SS semantics."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
import struct
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets.frames import Close, CloseCode

from src.proxy.connector import SS2022DuplexBridge
from src.proxy.ss_common import Reader
from src.proxy.ss2022 import SS2022Connection
from src.proxy.ss_aead import SSAEADConnection
from src.transports import ws_diagnostics
from src.transports.timing import WsAttemptTiming
from src.transports.ws_runtime import (
    read_next_responses_ws_step,
    read_until_first_responses_ws_visible_event,
)


class Raw:
    def __init__(self, *events):
        self.events = list(events)
        self.calls = []

    async def readexactly(self, count):
        self.calls.append(count)
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return event


class FakeAead:
    def __init__(self, *plaintext):
        self.plaintext = list(plaintext)

    def decrypt(self, nonce, ciphertext, aad):
        result = self.plaintext.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


@pytest.mark.parametrize('method', ['read', 'readall'])
@pytest.mark.parametrize('kind', ['eof', 'truncated', 'reset', 'os_timeout'])
@pytest.mark.asyncio
async def test_ss_records_original_read_end_without_changing_eof_contract(method, kind):
    errors = {
        'eof': asyncio.IncompleteReadError(b'', 18),
        'truncated': asyncio.IncompleteReadError(b'ciphertext', 18),
        'reset': ConnectionResetError(104, 'secret error argument'),
        'os_timeout': TimeoutError(110, 'secret error argument'),
    }
    error = errors[kind]
    reader = Reader(Raw(error), None, bytearray(12))
    assert await getattr(reader, method)() == b''
    end = reader.read_termination
    assert end.phase == 'length'
    assert end.error_type == type(error).__name__
    assert end.errno == getattr(error, 'errno', None)
    if isinstance(error, asyncio.IncompleteReadError):
        assert end.expected_bytes == 18
        assert end.partial_bytes == len(error.partial)
    else:
        assert end.expected_bytes is None and end.partial_bytes is None
    assert 'ciphertext' not in repr(end)
    assert 'secret error argument' not in repr(end)


@pytest.mark.asyncio
async def test_ss_distinguishes_payload_truncation_even_without_partial_payload():
    reader = Reader(
        Raw(b'length ciphertext', asyncio.IncompleteReadError(b'', 21)),
        FakeAead(struct.pack('!H', 5)), bytearray(12),
    )
    assert await reader.read() == b''
    assert reader.read_termination.phase == 'payload'
    assert reader.read_termination.expected_bytes == 21
    assert reader.read_termination.partial_bytes == 0


@pytest.mark.parametrize('method', ['read', 'readall'])
@pytest.mark.asyncio
async def test_ss_decode_error_still_raises_same_exception(method):
    error = ValueError('secret decryption detail')
    reader = Reader(Raw(b'length ciphertext'), FakeAead(error), bytearray(12))
    with pytest.raises(ValueError) as caught:
        await getattr(reader, method)()
    assert caught.value is error
    assert reader.read_termination.phase == 'length_decrypt'
    assert reader.read_termination.error_type == 'ValueError'
    assert 'secret decryption detail' not in repr(reader.read_termination)


@pytest.mark.asyncio
async def test_ss_partial_reads_and_zero_read_are_unchanged_and_not_eof():
    raw = Raw(b'length ciphertext', b'payload ciphertext')
    reader = Reader(raw, FakeAead(struct.pack('!H', 3), b'abc'), bytearray(12))
    assert await reader.read(0) == b''
    assert raw.calls == []
    assert await reader.read(2) == b'ab'
    assert await reader.read(100) == b'c'
    assert raw.calls == [18, 19]
    assert reader.read_termination is None


@pytest.mark.asyncio
async def test_ss_readall_preserves_buffer_and_first_termination():
    reader = Reader(Raw(ConnectionResetError(104, 'first'), OSError(5, 'second')), None, bytearray(12))
    reader._buf = b'already read'
    assert await reader.readall() == b'already read'
    first = reader.read_termination
    assert await reader.read() == b''
    assert reader.read_termination is first
    assert first.error_type == 'ConnectionResetError'


@pytest.mark.parametrize('method', ['read', 'readall'])
@pytest.mark.asyncio
async def test_ss_cancellation_is_not_recorded_as_transport_failure(method):
    reader = Reader(Raw(asyncio.CancelledError()), None, bytearray(12))
    with pytest.raises(asyncio.CancelledError):
        await getattr(reader, method)()
    assert reader.read_termination is None


@pytest.mark.parametrize('cls', [SS2022Connection, SSAEADConnection])
@pytest.mark.asyncio
async def test_ss_connection_wrapper_exposes_same_bounded_metadata(cls):
    connection = object.__new__(cls)
    connection._reader = None
    assert connection.read_termination is None
    reader = Reader(Raw(ConnectionResetError(104, 'private')), None, bytearray(12))
    await reader.read()
    connection._reader = reader
    assert connection.read_termination is reader.read_termination


class ClosedWs:
    def __init__(self, error, *, headers=None, bridge=None):
        self.error = error
        self.request = SimpleNamespace(headers=headers or {})
        self.bridge = bridge

    async def recv(self):
        raise self.error


def tracker(**kwargs):
    state = dict(response_completed=False, response_failed=False, response_incomplete=False,
                 last_event={'type': 'response.output_item.added'})
    state.update(kwargs)
    return SimpleNamespace(**state)


def timing(request_id='request-one', round_id='round-one'):
    result = WsAttemptTiming(request_id=request_id, round_id=round_id, proxy_name='test-proxy', route_type='ss2022')
    result.mark_handshake_complete()
    return result


def records(caplog):
    return [json.loads(r.args[0]) for r in caplog.records if r.name == ws_diagnostics.logger.name]


@pytest.mark.parametrize('phase', ['before_visible', 'after_accept'])
@pytest.mark.parametrize('kind', ['peer', 'eof', 'local_ping', 'peer_ping'])
@pytest.mark.asyncio
async def test_reader_diagnostics_distinguish_closures_without_changing_outcomes(caplog, phase, kind):
    errors = {
        'peer': ConnectionClosedOK(Close(1000, 'normal transport close'), Close(1000, 'normal transport close'), True),
        'eof': ConnectionClosedError(None, None),
        'local_ping': ConnectionClosedError(None, Close(CloseCode.INTERNAL_ERROR, 'keepalive ping timeout')),
        'peer_ping': ConnectionClosedError(Close(1011, 'keepalive ping timeout'), Close(1011, 'keepalive ping timeout'), True),
    }
    error = errors[kind]
    ws = ClosedWs(error)
    context = timing()
    if phase == 'before_visible':
        step = await read_until_first_responses_ws_visible_event(ws, tracker(), channel_key='test', deadline_ts=0,
            first_wait=5, idle_timeout=120, timing=context)
        assert step.error_detail == f'upstream websocket closed: {error}'
    else:
        step = await read_next_responses_ws_step(ws, tracker(), channel_key='test', deadline_ts=0,
            idle_timeout=120, timing=context, closed_error_detail='upstream websocket closed', check_blacklist=False)
        assert step.error_detail == 'upstream websocket closed'
    assert step.outcome == ('upstream_closed' if kind == 'peer_ping' else 'connection_lifecycle')
    log, = records(caplog)
    assert log['request_id'] == 'request-one'
    assert log['round_id'] == 'round-one'
    assert log['proxy_name'] == 'test-proxy'
    assert log['phase'] == phase
    assert log['last_event_type'] == 'response.output_item.added'
    assert log['ws']['local_keepalive_timeout'] is (kind == 'local_ping')
    if kind == 'local_ping':
        assert log['ws']['received'] is None
        assert log['ws']['sent'] == {'code': 1011, 'reason': 'keepalive ping timeout'}
    if kind == 'peer':
        assert log['ws']['received']['code'] == 1000
        assert log['ws']['received_then_sent'] is True


@pytest.mark.parametrize('flag', ['response_completed', 'response_failed', 'response_incomplete'])
def test_known_terminal_close_does_not_add_warning(caplog, flag):
    ws_diagnostics.log_ws_close(ClosedWs(ConnectionClosedError(None, None)), tracker(**{flag: True}),
        ConnectionClosedError(None, None), phase='after_accept', timing=timing())
    assert records(caplog) == []


def test_one_diagnostic_per_round_but_reused_connection_gets_new_request(caplog):
    error = ConnectionClosedError(None, None)
    ws = ClosedWs(error)
    first = timing()
    before = asdict(first.snapshot(terminal=True))
    ws_diagnostics.log_ws_close(ws, tracker(), error, phase='after_accept', timing=first)
    ws_diagnostics.log_ws_close(ws, tracker(), error, phase='after_accept', timing=first)
    # Only the diagnostic marker changes; timing measurements aren't finalized.
    assert first.snapshot().outcome is None
    assert first.snapshot().round_id == before['round_id']
    second = timing('request-one:ws:2', 'round-two')
    ws_diagnostics.log_ws_close(ws, tracker(), error, phase='before_visible', timing=second)
    assert [(r['request_id'], r['round_id']) for r in records(caplog)] == [
        ('request-one', 'round-one'), ('request-one:ws:2', 'round-two'),
    ]


@pytest.mark.asyncio
async def test_diagnostic_logger_failure_cannot_break_existing_error_path(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('logging failed')
    monkeypatch.setattr(ws_diagnostics.logger, 'warning', fail)
    result = await read_next_responses_ws_step(ClosedWs(ConnectionClosedError(None, None)), tracker(),
        channel_key='test', deadline_ts=0, idle_timeout=120, timing=timing(),
        closed_error_detail='upstream websocket closed', check_blacklist=False)
    assert result.outcome == 'connection_lifecycle'
    assert result.error_detail == 'upstream websocket closed'


def test_diagnostics_redact_actual_handshake_values_and_do_not_log_exception_args(caplog):
    first_secret = 'opaque-A/with+symbols='
    second_secret = 'another-private-credential'
    cookie_secret = 'private-cookie-value'
    headers = Headers()
    headers['Authorization'] = 'Bearer ' + first_secret
    headers['Authorization'] = 'Bearer ' + second_secret
    headers['Cookie'] = 'session=' + cookie_secret
    reason = f'peer {first_secret} {quote(second_secret, safe="")} {cookie_secret}\npassword="short value"'
    error = ConnectionClosedOK(Close(1000, reason), Close(1000, reason), True)
    error.__cause__ = OSError(104, 'PRIVATE_EXCEPTION_BODY')
    ws_diagnostics.log_ws_close(ClosedWs(error, headers=headers), tracker(), error, phase='after_accept', timing=timing())
    log, = records(caplog)
    encoded = json.dumps(log)
    for private in [first_secret, second_secret, cookie_secret, 'short value', 'PRIVATE_EXCEPTION_BODY']:
        assert private not in encoded
    assert '<redacted>' in log['ws']['received']['reason']
    assert '\n' not in log['ws']['received']['reason']
    assert log['ws']['exceptions'][1]['errno'] == 104
    assert 'headers' not in log and 'frames' not in log


def test_diagnostic_reasons_are_bounded_and_unknowns_are_not_invented(caplog):
    reason = 'backend overloaded ' * 1000
    error = ConnectionClosedOK(Close(1000, reason), Close(1000, reason), True)
    ws_diagnostics.log_ws_close(ClosedWs(error), tracker(last_event=None), error, phase='before_visible')
    log, = records(caplog)
    assert len(log['ws']['received']['reason']) == 256
    assert log['request_id'] is None and log['round_total_ms'] is None
    assert log['ss_bridge'] is None and log['last_event_type'] is None
    assert len(json.dumps(log)) < 3000


@pytest.mark.asyncio
async def test_actual_ss_bridge_retains_read_failure_before_ws_owner_cleanup(caplog):
    reader = Reader(Raw(ConnectionResetError(104, 'private transport argument')), None, bytearray(12))
    class Tunnel:
        close_count = 0
        @property
        def read_termination(self):
            return reader.read_termination
        async def read(self, n):
            return await reader.read(n)
        async def write(self, data):
            pass
        async def close(self):
            self.close_count += 1
    tunnel = Tunnel()
    bridge = await SS2022DuplexBridge.create(tunnel)
    await asyncio.wait_for(bridge.wait_closed(), timeout=1)
    assert bridge.terminal.direction == 'ss_to_application_eof'
    assert bridge.terminal.cause is None  # existing EOF behavior is unchanged
    error = ConnectionClosedError(None, None)
    ws_diagnostics.log_ws_close(ClosedWs(error, bridge=bridge), tracker(), error, phase='after_accept', timing=timing())
    log, = records(caplog)
    assert log['ss_bridge']['direction'] == 'ss_to_application_eof'
    assert log['ss_bridge']['read_termination']['error_type'] == 'ConnectionResetError'
    assert log['ss_bridge']['read_termination']['errno'] == 104
    await bridge.aclose()
    assert tunnel.close_count == 1

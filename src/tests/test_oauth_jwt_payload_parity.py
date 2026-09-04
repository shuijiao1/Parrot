"""Parity contract for the OpenAI and xAI unsigned JWT payload decoders."""

from __future__ import annotations

import os as _ap_os
import sys as _ap_sys

_ap_sys.path.insert(0, _ap_os.path.dirname(_ap_os.path.dirname(
    _ap_os.path.dirname(_ap_os.path.abspath(__file__))
)))
from src.tests import _isolation

_isolation.isolate()

import base64
import json
from types import SimpleNamespace

import pytest

from src.oauth import openai, xai


@pytest.fixture(params=(openai, xai), ids=("openai", "xai"))
def provider(request):
    return request.param


def _json_token(value, *, padded: bool = False) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    payload = base64.urlsafe_b64encode(raw).decode("ascii")
    if not padded:
        payload = payload.rstrip("=")
    return f"header.{payload}.signature"


def _raw_token(raw: bytes, *, padded: bool = False) -> str:
    payload = base64.urlsafe_b64encode(raw).decode("ascii")
    if not padded:
        payload = payload.rstrip("=")
    return f"header.{payload}.signature"


@pytest.mark.parametrize("padded", (False, True), ids=("auto-padding", "explicit-padding"))
def test_valid_payload_and_padding_parity(provider, padded):
    claims = {"sub": "user-1", "name": "雪"}
    assert provider.decode_id_token(_json_token(claims, padded=padded)) == claims


@pytest.mark.parametrize(
    ("token", "message"),
    (
        ("", "invalid JWT: got ''"),
        ("only-two.parts", "invalid JWT: got 'only-two.parts'"),
        ("a.b.c.d", "invalid JWT: expected 3 parts, got 4"),
    ),
)
def test_malformed_parts_preserve_provider_error(provider, token, message):
    with pytest.raises(provider.IDTokenError) as caught:
        provider.decode_id_token(token)
    assert str(caught.value) == message


@pytest.mark.parametrize(
    ("token", "message", "cause_type"),
    (
        (
            "header.a.signature",
            "decode base64: Invalid base64-encoded string: number of data characters (1) "
            "cannot be 1 more than a multiple of 4",
            "Error",
        ),
        (
            "header.雪.signature",
            "decode base64: string argument should contain only ASCII characters",
            "ValueError",
        ),
    ),
)
def test_malformed_base64_preserves_provider_error(provider, token, message, cause_type):
    with pytest.raises(provider.IDTokenError) as caught:
        provider.decode_id_token(token)
    assert str(caught.value) == message
    assert type(caught.value.__cause__).__name__ == cause_type


def test_base64_decoder_tolerance_is_unchanged(provider):
    claims = {"accepted": True}
    payload = _json_token(claims).split(".")[1]
    token_with_ignored_characters = f"header.!!!!{payload}.signature"
    assert provider.decode_id_token(token_with_ignored_characters) == claims


@pytest.mark.parametrize(
    ("raw", "message", "cause_type"),
    (
        (b"not-json", "parse JSON: Expecting value: line 1 column 1 (char 0)", "JSONDecodeError"),
        (
            b"\xff",
            "parse JSON: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
            "UnicodeDecodeError",
        ),
    ),
)
def test_malformed_json_and_unicode_preserve_provider_error(
    provider, raw, message, cause_type,
):
    with pytest.raises(provider.IDTokenError) as caught:
        provider.decode_id_token(_raw_token(raw))
    assert str(caught.value) == message
    assert type(caught.value.__cause__).__name__ == cause_type


@pytest.mark.parametrize("value", ([1, 2], None, "scalar"), ids=("array", "null", "string"))
def test_non_object_payload_without_exp_check_is_returned_unchanged(provider, value):
    assert provider.decode_id_token(_json_token(value)) == value


def test_non_object_payload_with_exp_check_preserves_attribute_error(provider):
    with pytest.raises(AttributeError) as caught:
        provider.decode_id_token(_json_token([1, 2]), verify_exp=True)
    assert str(caught.value) == "'list' object has no attribute 'get'"


@pytest.mark.parametrize(
    "claims",
    ({}, {"exp": None}, {"exp": "1000"}, {"exp": 1.5}, {"exp": 0}, {"exp": -1}),
    ids=("missing", "none", "string", "float", "zero", "negative"),
)
def test_missing_or_invalid_exp_is_not_rejected(provider, monkeypatch, claims):
    monkeypatch.setattr(provider, "time", SimpleNamespace(time=lambda: 10_000.0))
    assert provider.decode_id_token(_json_token(claims), verify_exp=True) == claims


@pytest.mark.parametrize(
    ("now", "expired"),
    ((1120.0, False), (1120.000001, True)),
    ids=("exact-boundary-valid", "past-boundary-expired"),
)
def test_expiry_uses_strict_seconds_boundary_and_skew(provider, monkeypatch, now, expired):
    monkeypatch.setattr(provider, "time", SimpleNamespace(time=lambda: now))
    token = _json_token({"exp": 1000})
    if expired:
        with pytest.raises(provider.IDTokenError, match=r"^id_token expired \(exp=1000\)$"):
            provider.decode_id_token(token, verify_exp=True)
    else:
        assert provider.decode_id_token(token, verify_exp=True) == {"exp": 1000}


@pytest.mark.parametrize(
    ("exp", "expired"),
    ((1_699_999_000, True), (1_699_999_000_000, False)),
    ids=("seconds-expired", "millisecond-value-not-converted"),
)
def test_exp_is_compared_as_raw_seconds_without_unit_conversion(
    provider, monkeypatch, exp, expired,
):
    monkeypatch.setattr(provider, "time", SimpleNamespace(time=lambda: 1_700_000_000.0))
    token = _json_token({"exp": exp})
    if expired:
        with pytest.raises(provider.IDTokenError) as caught:
            provider.decode_id_token(token, verify_exp=True, skew_seconds=120)
        assert str(caught.value) == f"id_token expired (exp={exp})"
    else:
        assert provider.decode_id_token(
            token, verify_exp=True, skew_seconds=120,
        ) == {"exp": exp}


def test_verify_exp_false_does_not_call_provider_clock(provider, monkeypatch):
    def _unexpected_clock_call():
        raise AssertionError("clock must not be read when verify_exp is false")

    monkeypatch.setattr(provider, "time", SimpleNamespace(time=_unexpected_clock_call))
    assert provider.decode_id_token(_json_token({"exp": 1})) == {"exp": 1}


def test_provider_dependency_monkeypatch_seams_are_preserved(provider, monkeypatch):
    calls = []

    def _decode(payload):
        calls.append(("base64", payload))
        return b"provider-json"

    def _loads(raw):
        calls.append(("json", raw))
        return {"exp": 1000, "source": "provider seam"}

    def _time():
        calls.append(("time", None))
        return 1000.0

    monkeypatch.setattr(provider, "base64", SimpleNamespace(urlsafe_b64decode=_decode))
    monkeypatch.setattr(provider, "json", SimpleNamespace(loads=_loads))
    monkeypatch.setattr(provider, "time", SimpleNamespace(time=_time))

    assert provider.decode_id_token(
        "header.payload.signature", verify_exp=True,
    ) == {"exp": 1000, "source": "provider seam"}
    assert calls == [
        ("base64", "payload="),
        ("json", "provider-json"),
        ("time", None),
    ]


def test_provider_error_types_remain_distinct():
    assert issubclass(openai.IDTokenError, ValueError)
    assert issubclass(xai.IDTokenError, ValueError)
    assert openai.IDTokenError is not xai.IDTokenError

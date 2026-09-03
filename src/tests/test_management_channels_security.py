from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from src.management_api.channels_security import redact_credential_text
from src.management_control.channels import service as channel_service
from src.tests.test_management_channels_api import (
    _build_app,
    _manual_create,
    _reset_channels,
    _session,
    _wait_operation,
)


_ASSIGNMENT_KEYS = (
    "credential",
    "Credential",
    "CREDENTIAL",
    "exchangeCredential",
    "ExchangeCredential",
    "exchange_credential",
    "exchange-credential",
    "EXCHANGECREDENTIAL",
    "EXCHANGE_CREDENTIAL",
    "EXCHANGE-CREDENTIAL",
    "deploymentCredential",
    "deployment_credential",
    "deployment-credential",
    "DEPLOYMENTCREDENTIAL",
    "exchangeSecret",
    "exchange_secret",
    "exchange-secret",
    "EXCHANGESECRET",
    "challengeSecret",
    "challenge_secret",
    "challenge-secret",
    "sessionSecret",
    "session_secret",
    "session-secret",
    "token",
    "key",
    "secret",
    "rotationToken",
    "rotation_token",
    "rotation-token",
    "ROTATIONTOKEN",
    "signingKey",
    "signing_key",
    "signing-key",
    "SIGNINGKEY",
    "webhookSecret",
    "webhook_secret",
    "webhook-secret",
    "WEBHOOKSECRET",
)
_ORDINARY_CONTEXT = (
    "ordinary token count=42; token usage is 42; basic routing mode; "
    "Basic routing mode; Bearer support is enabled"
)


@pytest.fixture(autouse=True)
def isolated_channel_state():
    _reset_channels()
    yield
    _reset_channels()


def _assignment_error_samples():
    markers = tuple(
        f"assignment-sensitive-marker-{index}" for index in range(len(_ASSIGNMENT_KEYS))
    )
    assignments = dict(zip(_ASSIGNMENT_KEYS, markers))
    equals = " ".join(
        f"{key}={marker}" for key, marker in assignments.items()
    )
    colons = " ".join(
        f"{key}: {marker}" for key, marker in assignments.items()
    )
    structured = json.dumps(assignments, separators=(",", ":"))
    double_encoded = json.dumps(structured)
    escaped_fragment = structured.replace('"', r'\"')
    auth_markers = ("bearer-sensitive-marker", "basic-sensitive-marker")
    samples = (
        f"provider failed; {_ORDINARY_CONTEXT}; {equals}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; {colons}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; {structured}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; {double_encoded}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; payload={escaped_fragment}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; Bearer {auth_markers[0]}; "
        f"Basic {auth_markers[1]}; retry later",
    )
    return markers + auth_markers, samples


@pytest.mark.parametrize("key", _ASSIGNMENT_KEYS)
def test_credential_key_classifier_has_exact_assignment_output(key):
    assert redact_credential_text(f"{key}=marker") == f"{key}=[REDACTED]"
    assert redact_credential_text(f'{{"{key}":"marker"}}') == (
        f'{{"{key}":"[REDACTED]"}}'
    )


@pytest.mark.parametrize(
    "ordinary",
    (
        "basic routing mode",
        "Basic routing mode",
        "Bearer support is enabled",
        "Bearer support is enabled.",
        "monkey=value",
        "keyboard: qwerty",
        "secret rotation completed",
        "token count=42; key count: 3; token usage is 42",
    ),
)
def test_business_text_is_preserved_exactly(ordinary):
    assert redact_credential_text(ordinary) == ordinary


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("Bearer marker", "Bearer [REDACTED]"),
        (
            "request failed: Bearer bearer-sensitive-marker; retry",
            "request failed: Bearer [REDACTED]; retry",
        ),
        (
            "request failed: Basic basic-sensitive-marker. retry",
            "request failed: Basic [REDACTED]. retry",
        ),
        (
            "Basic dXNlcjpwYXNz denied",
            "Basic [REDACTED] denied",
        ),
        (
            "Bearer header-segment.payload-segment.signature-segment",
            "Bearer [REDACTED]",
        ),
        (
            'Basic "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" denied',
            'Basic "[REDACTED]" denied',
        ),
        (
            "upstream returned Bearer aZ9kLm2Qp7Vx4Nc8Rt1",
            "upstream returned Bearer [REDACTED]",
        ),
        (
            "Bearer abcdefghijklmnopqrstuvwxyzabcdef",
            "Bearer [REDACTED]",
        ),
    ),
)
def test_auth_scheme_redacts_only_credential_shaped_values_with_exact_output(
    source, expected,
):
    assert redact_credential_text(source) == expected


def test_assignment_credential_families_are_redacted_without_business_false_positives():
    ordinary = (
        f"{_ORDINARY_CONTEXT}; secret rotation completed; "
        "keyboard key count=3; monkey=value"
    )
    assert redact_credential_text(ordinary) == ordinary

    markers, samples = _assignment_error_samples()
    for source in samples:
        original = source[:]
        safe = redact_credential_text(source)
        assert source == original
        assert safe and _ORDINARY_CONTEXT in safe
        assert "provider failed" in safe and "retry later" in safe
        assert "[REDACTED]" in safe
        assert all(marker not in safe for marker in markers)


def test_assignment_secrets_are_absent_from_http_audit_operation_and_openapi(
    tmp_path, monkeypatch,
):
    markers, samples = _assignment_error_samples()
    raw_usage = {
        "status": "error",
        "error": samples[0],
        "error_at": 1_700_000_000_000,
    }
    monkeypatch.setattr(channel_service.provider_usage, "spec_for", lambda channel: object())
    monkeypatch.setattr(channel_service.provider_usage, "cached", lambda channel: raw_usage)
    monkeypatch.setattr(
        channel_service.provider_usage, "schedule_refresh", lambda *args, **kwargs: True
    )
    app, runtime = _build_app(tmp_path)

    response_evidence = []
    with TestClient(app) as client:
        auth = _session(client)
        created = client.post(
            "/api/management/v1/channels",
            json=_manual_create("Usage Assignment Security"),
            headers=auth,
        )
        assert created.status_code == 201, created.text
        response_evidence.append(created.text)

        for source in samples:
            raw_usage["error"] = source
            before = raw_usage.copy()
            response = client.get(
                "/api/management/v1/channels/api:Usage%20Assignment%20Security",
                headers=auth,
            )
            assert response.status_code == 200, response.text
            response_evidence.append(response.text)
            safe_error = response.json()["data"]["providerUsage"]["error"]
            assert safe_error and _ORDINARY_CONTEXT in safe_error
            assert all(marker not in safe_error for marker in markers)
            assert raw_usage == before

        submitted = client.post(
            "/api/management/v1/channels/api:Usage%20Assignment%20Security/actions/refresh-usage",
            headers=auth,
        )
        assert submitted.status_code == 202, submitted.text
        terminal = _wait_operation(client, auth, submitted.json()["data"]["id"])
        assert terminal["status"] == "succeeded", terminal
        response_evidence.extend((submitted.text, json.dumps(terminal)))

    boundary_evidence = {
        "response": "".join(response_evidence),
        "audit": json.dumps(runtime.state_store.audit_snapshot()),
        "operation": json.dumps(runtime.operations._items, default=str),
        "openapi": json.dumps(app.openapi()),
    }
    for boundary, evidence in boundary_evidence.items():
        assert all(marker not in evidence for marker in markers), boundary
    runtime.close()

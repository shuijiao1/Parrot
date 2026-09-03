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
    "exchangeSecret",
    "exchange_secret",
    "exchange-secret",
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
    "signingKey",
    "signing_key",
    "signing-key",
    "webhookSecret",
    "webhook_secret",
    "webhook-secret",
)
_ORDINARY_CONTEXT = "ordinary token count=42; token usage is 42"


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
    samples = (
        f"provider failed; {_ORDINARY_CONTEXT}; {equals}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; {colons}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; {structured}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; {double_encoded}; retry later",
        f"provider failed; {_ORDINARY_CONTEXT}; payload={escaped_fragment}; retry later",
    )
    return markers, samples


def test_assignment_credential_families_are_redacted_without_business_false_positives():
    ordinary = (
        "ordinary token count=42; token usage is 42; "
        "secret rotation completed; keyboard key count=3; monkey=value"
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

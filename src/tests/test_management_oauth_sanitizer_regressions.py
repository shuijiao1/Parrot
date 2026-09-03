from __future__ import annotations

import base64

import pytest

from src.management_control.oauth.contracts import is_sensitive_key, sanitize_text
from src.tests.test_management_oauth_api import ACCOUNT_ID, auth_client, request


LONG_ALPHA_TOKEN = "abcdefghijklmnopqrstuvwxyzabcdef"
SYNTHETIC_CREDENTIAL = "SYNTHETIC-CREDENTIAL-MARKER-987654"


@pytest.mark.parametrize(
    "key",
    (
        # Generic, camel, snake, delimited uppercase, and known concatenated families.
        "token",
        "key",
        "secret",
        "credential",
        "providerToken",
        "upstreamSecret",
        "upstreamCredential",
        "provider_secret",
        "service_key",
        "PROVIDER_TOKEN",
        "SERVICE_CREDENTIAL",
        "EXCHANGESECRET",
        # Generic ALL_CAPS concatenated suffixes from the regression report.
        "PROVIDERTOKEN",
        "UPSTREAMCREDENTIAL",
        "SERVICESECRET",
        "SERVICEKEY",
        "OTHERTOKEN",
        "OTHERSECRET",
        "OTHERKEY",
    ),
)
def test_sensitive_key_classifier_covers_credential_families(key):
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    (
        # Credential terms in public identifier names are metadata, not secrets.
        "upstreamKeyId",
        "publicKeyId",
        "tokenId",
        "credentialID",
        "upstream_key_id",
        "PUBLIC_KEY_ID",
        # Existing public metadata and ordinary-word behavior must remain stable.
        "channelKey",
        "account_key",
        "keyId",
        "credentialConfigured",
        "tokenCount",
        "sessionCount",
        "monkey",
        "MONKEY",
        "hockey",
        "HOCKEY",
        "turkey",
        "TURKEY",
        "donkey",
        "DONKEY",
        "passkey",
        "PASSKEY",
        "keyboard",
        "KEYBOARD",
    ),
)
def test_sensitive_key_classifier_preserves_public_identifiers_and_words(key):
    assert not is_sensitive_key(key)


def test_auth_text_redaction_is_bidirectional_and_keeps_reasonable_formatting():
    basic = base64.b64encode(b"user:synthetic-password").decode()
    sensitive = {
        f"Bearer {LONG_ALPHA_TOKEN}": "Bearer [REDACTED]",
        f"authorization=Bearer {LONG_ALPHA_TOKEN}": "authorization=Bearer [REDACTED]",
        f'Authorization: "Bearer {LONG_ALPHA_TOKEN}"': 'Authorization: "Bearer [REDACTED]"',
        rf'{{\"authorization\":\"Bearer {LONG_ALPHA_TOKEN}\"}}': (
            r'{\"authorization\":\"Bearer [REDACTED]\"}'
        ),
        f"authorization=Basic {basic}": "authorization=Basic [REDACTED]",
        f"Basic {basic}": "Basic [REDACTED]",
    }
    for raw, expected in sensitive.items():
        assert sanitize_text(raw) == expected
        assert sanitize_text(sanitize_text(raw)) == expected
        assert LONG_ALPHA_TOKEN not in expected
        assert basic not in expected
        assert "[REDACTED] [REDACTED]" not in expected

    ordinary = (
        "Bearer routing-mode",
        "bearer support-enabled",
        "Basic routing-mode",
        "basic request-routing",
        "Bearer ordinary.word",
        "Basic routing mode",
        "basic routing mode",
        "BASIC ROUTING MODE",
        "Bearer support is enabled",
        "bearer support is enabled",
        "BEARER SUPPORT IS ENABLED",
    )
    for prose in ordinary:
        assert sanitize_text(prose) == prose

    assert (
        sanitize_text("https://URL_USERNAME_ONLY_MARKER@example.invalid/path")
        == "https://[REDACTED]@example.invalid/path"
    )
    assert (
        sanitize_text(
            r"https:\/\/ESCAPED_URL_USER_MARKER:synthetic@example.invalid/path"
        )
        == r"https:\/\/[REDACTED]@example.invalid/path"
    )


def test_http_runtime_errors_and_operation_results_apply_the_same_boundary(tmp_path):
    client, headers, _, _, backend = auth_client(tmp_path)
    basic = base64.b64encode(b"user:synthetic-password").decode()
    ordinary_prose = (
        "Bearer routing-mode",
        "bearer support-enabled",
        "Basic routing-mode",
        "basic request-routing",
        "Bearer ordinary.word",
        "Basic routing mode",
        "basic routing mode",
        "Bearer support is enabled",
        "bearer support is enabled",
    )
    public_assignments = (
        "upstreamKeyId=upstream-key-id-public",
        "publicKeyId=public-key-id-public",
        "channelKey=oauth:public-channel",
        "account_key=oauth:public-account",
        "MONKEY=value",
        "HOCKEY=goal",
        "TURKEY=dinner",
        "DONKEY=value",
        "PASSKEY=value",
        "KEYBOARD=value",
    )
    sensitive_fragments = (
        f"Bearer {LONG_ALPHA_TOKEN}",
        f"authorization=Bearer {LONG_ALPHA_TOKEN}",
        f'Authorization: "Bearer {LONG_ALPHA_TOKEN}"',
        rf'{{\"authorization\":\"Bearer {LONG_ALPHA_TOKEN}\"}}',
        f"authorization=Basic {basic}",
        f"Basic {basic}",
        f"token={SYNTHETIC_CREDENTIAL}",
        f"providerToken={SYNTHETIC_CREDENTIAL}",
        f"provider_secret={SYNTHETIC_CREDENTIAL}",
        f"SERVICE_CREDENTIAL={SYNTHETIC_CREDENTIAL}",
        f"PROVIDERTOKEN={SYNTHETIC_CREDENTIAL}",
        f"UPSTREAMCREDENTIAL={SYNTHETIC_CREDENTIAL}",
        f"SERVICESECRET={SYNTHETIC_CREDENTIAL}",
        f"SERVICEKEY={SYNTHETIC_CREDENTIAL}",
        f"OTHERTOKEN={SYNTHETIC_CREDENTIAL}",
        f"OTHERSECRET={SYNTHETIC_CREDENTIAL}",
        f"OTHERKEY={SYNTHETIC_CREDENTIAL}",
        "https://URL_USERNAME_ONLY_MARKER@example.invalid/path",
        f"socks5://URL_USERNAME_MARKER:{SYNTHETIC_CREDENTIAL}@example.invalid/path",
    )
    raw = " | ".join((*ordinary_prose, *public_assignments, *sensitive_fragments))
    try:
        backend.cooldowns[0]["last_error"] = raw
        response = request(
            client, "GET", f"/oauth/accounts/{ACCOUNT_ID}", None, headers,
        )
        assert response.status_code == 200, response.text
        message = response.json()["data"]["runtimeErrors"][0]["message"]
        assert all(item in message for item in ordinary_prose)
        assert all(item in message for item in public_assignments)
        assert LONG_ALPHA_TOKEN not in message
        assert SYNTHETIC_CREDENTIAL not in message
        assert basic not in message
        assert "URL_USERNAME_ONLY_MARKER" not in message
        assert "URL_USERNAME_MARKER" not in message
        assert "authorization=Bearer [REDACTED]" in message
        assert 'Authorization: "Bearer [REDACTED]"' in message
        assert r'{\"authorization\":\"Bearer [REDACTED]\"}' in message
        assert "authorization=Basic [REDACTED]" in message
        assert "[REDACTED] [REDACTED]" not in message
        assert backend.cooldowns[0]["last_error"] == raw

        backend.sync_result = {
            "action": "updated",
            "account_key": ACCOUNT_ID,
            "upstreamKeyId": "upstream-key-id-public",
            "publicKeyId": "public-key-id-public",
            "channelKey": "oauth:public-channel",
            "PROVIDERTOKEN": SYNTHETIC_CREDENTIAL,
            "UPSTREAMCREDENTIAL": SYNTHETIC_CREDENTIAL,
            "SERVICESECRET": SYNTHETIC_CREDENTIAL,
            "SERVICEKEY": SYNTHETIC_CREDENTIAL,
            "OTHERTOKEN": SYNTHETIC_CREDENTIAL,
            "OTHERSECRET": SYNTHETIC_CREDENTIAL,
            "OTHERKEY": SYNTHETIC_CREDENTIAL,
            "providerToken": SYNTHETIC_CREDENTIAL,
            "provider_secret": SYNTHETIC_CREDENTIAL,
            "SERVICE_CREDENTIAL": SYNTHETIC_CREDENTIAL,
            "EXCHANGESECRET": SYNTHETIC_CREDENTIAL,
            "message": raw,
        }
        started = request(
            client,
            "POST",
            f"/oauth/accounts/{ACCOUNT_ID}/models/actions/sync",
            None,
            headers,
        )
        assert started.status_code == 202, started.text
        operation = client.get(
            f"/api/management/v1/operations/{started.json()['data']['id']}",
            headers=headers,
        )
        assert operation.status_code == 200, operation.text
        result = operation.json()["data"]["result"]
        assert result["accountId"] == ACCOUNT_ID
        assert result["upstreamKeyId"] == "upstream-key-id-public"
        assert result["publicKeyId"] == "public-key-id-public"
        assert result["channelKey"] == "oauth:public-channel"
        assert all(
            result[key] == "[REDACTED]"
            for key in (
                "PROVIDERTOKEN",
                "UPSTREAMCREDENTIAL",
                "SERVICESECRET",
                "SERVICEKEY",
                "OTHERTOKEN",
                "OTHERSECRET",
                "OTHERKEY",
                "providerToken",
                "providerSecret",
                "SERVICECREDENTIAL",
                "EXCHANGESECRET",
            )
        )
        assert LONG_ALPHA_TOKEN not in operation.text
        assert SYNTHETIC_CREDENTIAL not in operation.text
        assert basic not in operation.text
        assert "[REDACTED] [REDACTED]" not in operation.text
        assert backend.sync_result["PROVIDERTOKEN"] == SYNTHETIC_CREDENTIAL
        assert backend.sync_result["publicKeyId"] == "public-key-id-public"
    finally:
        client.__exit__(None, None, None)

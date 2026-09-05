from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from src import config, provider_usage
from src.channel import registry
from src.management_control import ManagementError, ManagementErrorCode
from src.management_control.channels import (
    ChannelControl,
    ChannelCreateCommand,
    ChannelModel,
    ChannelProtocol,
    ChannelUpdateCommand,
)
from src.tests import test_management_channels_api as api_support


def _preset_command(name: str = "M13 Control") -> ChannelCreateCommand:
    return ChannelCreateCommand(
        name=name,
        base_url=None,
        api_key=api_support.FAKE_CHANNEL_SECRET,
        protocol=ChannelProtocol.ANTHROPIC,
        models=(ChannelModel(real="kimi-for-coding", alias="kimi-for-coding"),),
        provider_id="kimi",
        provider_preset_id="code",
    )


def _channel_state(channel_id: str) -> tuple[dict, object, tuple]:
    entry = copy.deepcopy(config.get()["channels"])
    channel = registry.get_channel(channel_id)
    assert channel is not None
    runtime = (
        channel.key,
        channel.base_url,
        channel.api_path,
        channel.protocol,
        channel.provider_id,
        channel.provider_preset_id,
    )
    return entry, channel, runtime


def _assert_channel_state(channel_id: str, expected: tuple[dict, object, tuple]) -> None:
    entries, channel, runtime = expected
    assert config.get()["channels"] == entries
    assert registry.get_channel(channel_id) is channel
    assert (
        channel.key,
        channel.base_url,
        channel.api_path,
        channel.protocol,
        channel.provider_id,
        channel.provider_preset_id,
    ) == runtime


def test_control_rejects_invalid_final_provider_combinations_before_registry_write():
    api_support._reset_channels()
    try:
        control = ChannelControl()
        created = control.create_channel(api_support.channel_menu._ctx(42), _preset_command()).channel
        before = _channel_state(created.id)
        assert created.provider_usage.supported is True

        invalid = (
            (ChannelUpdateCommand(provider_id=None), ManagementErrorCode.VALIDATION_FAILED),
            (ChannelUpdateCommand(provider_preset_id=None), ManagementErrorCode.VALIDATION_FAILED),
            (
                ChannelUpdateCommand(
                    provider_id="unregistered-provider",
                    provider_preset_id="unregistered-preset",
                ),
                ManagementErrorCode.UNSUPPORTED_VALUE,
            ),
            (
                ChannelUpdateCommand(provider_id="deepseek"),
                ManagementErrorCode.UNSUPPORTED_VALUE,
            ),
            (
                ChannelUpdateCommand(protocol=ChannelProtocol.OPENAI_RESPONSES),
                ManagementErrorCode.UNSUPPORTED_VALUE,
            ),
        )
        for command, code in invalid:
            with pytest.raises(ManagementError) as caught:
                control.update_channel(
                    api_support.channel_menu._ctx(42),
                    created.id,
                    command,
                    expected_revision=created.revision,
                )
            assert caught.value.code is code
            _assert_channel_state(created.id, before)

        with pytest.raises(ManagementError) as caught:
            control.update_channel(
                api_support.channel_menu._ctx(42),
                created.id,
                ChannelUpdateCommand(
                    provider_id="unregistered-provider",
                    provider_preset_id="unregistered-preset",
                ),
                expected_revision="chrev_stale",
            )
        assert caught.value.code is ManagementErrorCode.REVISION_CONFLICT
        _assert_channel_state(created.id, before)
    finally:
        api_support._reset_channels()


def test_asgi_patch_rejects_invalid_combinations_and_preserves_legal_manual_endpoint(tmp_path):
    api_support._reset_channels()
    app, runtime = api_support._build_app(tmp_path)
    try:
        with TestClient(app) as client:
            auth = api_support._session(client)
            catalog_response = client.get(
                "/api/management/v1/channel-catalog", headers=auth,
            )
            assert catalog_response.status_code == 200
            for provider in catalog_response.json()["data"]["providers"]:
                for preset in provider["presets"]:
                    channel = SimpleNamespace(
                        provider_id=provider["id"], provider_preset_id=preset["id"],
                    )
                    assert preset["providerUsageSupported"] is (
                        provider_usage.spec_for(channel) is not None
                    )

            response = client.post(
                "/api/management/v1/channels",
                json=api_support._preset_create("M13 API"),
                headers=auth,
            )
            assert response.status_code == 201, response.text
            created = response.json()["data"]
            channel_id = created["id"]
            path = "/api/management/v1/channels/api:M13%20API"
            endpoint = (created["baseUrl"], created["apiPath"], created["url"])
            assert created["providerUsage"]["supported"] is True
            before = _channel_state(channel_id)

            invalid = (
                ({"providerId": None}, "VALIDATION_FAILED"),
                ({"providerPresetId": None}, "VALIDATION_FAILED"),
                (
                    {
                        "providerId": "unregistered-provider",
                        "providerPresetId": "unregistered-preset",
                    },
                    "UNSUPPORTED_VALUE",
                ),
                ({"providerId": "deepseek"}, "UNSUPPORTED_VALUE"),
                ({"protocol": "openai-responses"}, "UNSUPPORTED_VALUE"),
            )
            for body, code in invalid:
                failed = client.patch(
                    path,
                    json=body,
                    headers={**auth, "If-Match": created["revision"]},
                )
                assert failed.status_code == 422, failed.text
                assert failed.json()["error"]["code"] == code
                _assert_channel_state(channel_id, before)

            stale = client.patch(
                path,
                json={
                    "providerId": "unregistered-provider",
                    "providerPresetId": "unregistered-preset",
                },
                headers={**auth, "If-Match": "chrev_stale"},
            )
            assert stale.status_code == 409, stale.text
            assert stale.json()["error"]["code"] == "REVISION_CONFLICT"
            _assert_channel_state(channel_id, before)

            switched = client.patch(
                path,
                json={"providerId": "deepseek", "providerPresetId": "standard"},
                headers={**auth, "If-Match": created["revision"]},
            )
            assert switched.status_code == 200, switched.text
            switched_data = switched.json()["data"]
            assert (switched_data["providerId"], switched_data["providerPresetId"]) == (
                "deepseek", "standard",
            )
            assert (
                switched_data["baseUrl"], switched_data["apiPath"], switched_data["url"],
            ) == endpoint
            switched_live = registry.get_channel(channel_id)
            assert switched_data["providerUsage"]["supported"] is (
                provider_usage.spec_for(switched_live) is not None
            )

            cleared = client.patch(
                path,
                json={"providerId": None, "providerPresetId": None},
                headers={**auth, "If-Match": switched_data["revision"]},
            )
            assert cleared.status_code == 200, cleared.text
            cleared_data = cleared.json()["data"]
            assert cleared_data["providerId"] is None
            assert cleared_data["providerPresetId"] is None
            assert cleared_data["providerUsage"]["supported"] is False
            assert (
                cleared_data["baseUrl"], cleared_data["apiPath"], cleared_data["url"],
            ) == endpoint

            manual_endpoint = "https://manual.example.test/v1/messages"
            manual = client.patch(
                path,
                json={"baseUrl": manual_endpoint},
                headers={**auth, "If-Match": cleared_data["revision"]},
            )
            assert manual.status_code == 200, manual.text
            manual_data = manual.json()["data"]
            assert manual_data["url"] == manual_endpoint
            assert manual_data["providerId"] is None
            assert manual_data["providerPresetId"] is None
    finally:
        runtime.close()
        api_support._reset_channels()

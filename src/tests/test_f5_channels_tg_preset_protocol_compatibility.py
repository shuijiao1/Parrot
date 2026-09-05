from __future__ import annotations

import copy

from src import config
from src.channel import registry
from src.management_control.channels import (
    ChannelControl,
    ChannelCreateCommand,
    ChannelModel,
    ChannelProtocol,
)
from src.telegram.menus import channel_menu
from src.tests import test_management_channels_api as channel_support


CHANNEL_NAME = "F5 TG Preset"


def _preset_command() -> ChannelCreateCommand:
    return ChannelCreateCommand(
        name=CHANNEL_NAME,
        base_url=None,
        api_key=channel_support.FAKE_CHANNEL_SECRET,
        protocol=ChannelProtocol.ANTHROPIC,
        models=(ChannelModel(real="kimi-for-coding", alias="kimi-for-coding"),),
        provider_id="kimi",
        provider_preset_id="code",
    )


def _stored_entry() -> dict:
    return copy.deepcopy(next(
        entry
        for entry in config.get()["channels"]
        if entry.get("name") == CHANNEL_NAME
    ))


def test_tg_preset_channel_keeps_legacy_manual_protocol_switch() -> None:
    """Freeze the reachable TG helper behavior missed by TG-CH-04's manual channel."""
    channel_support._reset_channels()
    try:
        control = ChannelControl()
        created = control.create_channel(channel_menu._ctx(42), _preset_command()).channel
        assert (created.provider_id, created.provider_preset_id) == ("kimi", "code")

        channel_menu._control_update(
            CHANNEL_NAME,
            {"baseUrl": "https://manual.example.test"},
            42,
        )
        switched = channel_menu._control_update(
            CHANNEL_NAME,
            {"protocol": "openai-responses"},
            42,
        ).channel

        entry = _stored_entry()
        assert entry["providerId"] == "kimi"
        assert entry["providerPresetId"] == "code"
        assert entry["protocol"] == "openai-responses"
        assert entry["baseUrl"] == "https://manual.example.test"
        assert "apiPath" not in entry
        assert entry["cc_mimicry"] is False

        live = registry.get_channel(f"api:{CHANNEL_NAME}")
        assert live is not None
        assert switched.protocol is ChannelProtocol.OPENAI_RESPONSES
        assert (switched.provider_id, switched.provider_preset_id) == ("kimi", "code")
        assert switched.base_url == "https://manual.example.test"
        assert switched.api_path is None
        assert live.protocol == "openai-responses"
        assert (live.provider_id, live.provider_preset_id) == ("kimi", "code")
        assert live.base_url == "https://manual.example.test"
        assert live.api_path is None
    finally:
        channel_support._reset_channels()

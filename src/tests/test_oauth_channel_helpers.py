from __future__ import annotations

import pytest

from src.channel import (
    antigravity_oauth_channel,
    cursor_oauth_channel,
    openai_oauth_channel,
    xai_oauth_channel,
)
from src.channel.oauth_helpers import request_api_key_name


CHANNEL_HELPERS = (
    openai_oauth_channel._request_api_key_name,
    xai_oauth_channel._request_api_key_name,
    cursor_oauth_channel._request_api_key_name,
    antigravity_oauth_channel._request_api_key_name,
)


def test_oauth_channels_keep_private_helper_alias():
    assert all(helper is request_api_key_name for helper in CHANNEL_HELPERS)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({}, ""),
        ({"_parrot_api_key_name": "anthropic"}, "anthropic"),
        ({"_api_key_name": "openai", "_parrot_api_key_name": "anthropic"}, "openai"),
        ({"_api_key_name": 7, "_parrot_api_key_name": 9}, "7"),
        ({"_api_key_name": 0, "_parrot_api_key_name": 9}, "9"),
        ({"_api_key_name": None, "_parrot_api_key_name": False}, ""),
    ],
)
def test_request_api_key_name_preserves_priority_fallback_and_string_conversion(
    body, expected,
):
    assert request_api_key_name(body) == expected

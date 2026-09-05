from __future__ import annotations

from src import config
from src.openai import codex_identity
from src.openai.codex_constants import current_codex_protocol_profile


def test_isolated_config_tracks_packaged_current_codex_profile():
    selected = current_codex_protocol_profile()
    provider = config.get()["openaiOAuth"]

    assert provider["codexProfileAutoUpdate"] is True
    assert provider["codexCliVersion"] == selected.client_version
    assert provider["codexProtocolProfile"] == selected.profile_id


def test_identity_split_preserves_public_module_and_capture_monkeypatch_seam(monkeypatch):
    assert codex_identity.project_snapshot.__module__ == "src.openai.codex_identity"
    assert codex_identity.capture_turn_state.__module__ == "src.openai.codex_identity"

    observed = []

    def capture(translator_ctx, headers):
        observed.append((translator_ctx, headers))
        return True

    monkeypatch.setattr(codex_identity, "capture_turn_state", capture)
    translator_ctx = {"sentinel": True}
    headers = {"x-codex-turn-state": "opaque"}
    event = {"type": "response.metadata", "headers": headers}

    assert codex_identity.capture_turn_state_event(translator_ctx, event) is True
    assert observed == [(translator_ctx, headers)]

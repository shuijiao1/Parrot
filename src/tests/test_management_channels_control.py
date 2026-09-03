from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone

import pytest

from src import affinity, config, cooldown, state_db
from src.channel import registry
from src.management_auth import AuthMethod, Capability, ManagementPrincipal
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode
from src.management_control.channels import (
    ChannelCompatibility,
    ChannelControl,
    ChannelCreateCommand,
    ChannelListQuery,
    ChannelModel,
    ChannelProtocol,
    ChannelSort,
    ChannelUpdateCommand,
    CompatibilityFeature,
    CompatibilityMode,
    DiscoveryCommand,
    DraftProbeCommand,
    SortDirection,
)
from src.management_control.channels import service as channel_service
from src.openai.channel.registration import register_factories


def _principal(*capabilities: Capability) -> ManagementPrincipal:
    return ManagementPrincipal.with_capabilities(
        subject_id="channels-test",
        auth_method=AuthMethod.MANAGEMENT_KEY,
        capabilities=capabilities,
        issued_at=datetime.now(timezone.utc),
        session_id="session-channels-test",
    )


def _context(*capabilities: Capability) -> ManagementContext:
    return ManagementContext(request_id="request-channels-test", actor=_principal(*capabilities))


ADMIN_CONTEXT = ManagementContext(
    request_id="request-channels-admin",
    actor=ManagementPrincipal.administrator(
        subject_id="channels-admin", auth_method=AuthMethod.MANAGEMENT_KEY,
    ),
)


def _reset_channels() -> None:
    state_db.init()
    register_factories()
    state_db.error_delete()
    state_db.affinity_delete()
    state_db.client_affinity_delete()
    for module in (cooldown, affinity):
        module._initialized = False
    cooldown.init()
    affinity.init()
    affinity.client_init()
    config.update(lambda current: current.__setitem__("channels", []))
    registry.rebuild_from_config()


@pytest.fixture(autouse=True)
def isolated_channel_state():
    _reset_channels()
    yield
    _reset_channels()


def _command(name: str, *, protocol: ChannelProtocol = ChannelProtocol.ANTHROPIC):
    return ChannelCreateCommand(
        name=name,
        base_url="https://provider.example.test/v1/messages" if protocol is ChannelProtocol.ANTHROPIC
        else "https://provider.example.test/v1/chat/completions",
        api_key="sk-fake-channel-key",
        protocol=protocol,
        models=(ChannelModel(real="model-real", alias="model-alias"),),
        max_concurrent=3,
        compatibility=ChannelCompatibility(
            context_1m=CompatibilityFeature(CompatibilityMode.FORCE, ("model-real",)),
        ),
    )


def test_control_crud_filter_sort_revision_reorder_and_secret_boundary():
    control = ChannelControl()
    alpha = control.create_channel(ADMIN_CONTEXT, _command("Alpha"))
    beta = control.create_channel(
        ADMIN_CONTEXT, _command("Beta", protocol=ChannelProtocol.OPENAI_CHAT)
    )

    assert alpha.channel.id == "api:Alpha"
    assert alpha.channel.base_url == "https://provider.example.test"
    assert alpha.channel.api_path == "/v1/messages"
    assert alpha.channel.api_key_configured is True
    assert not hasattr(alpha.channel, "api_key")
    assert "sk-fake-channel-key" not in repr(alpha.channel)

    page = control.list_channels(ADMIN_CONTEXT, ChannelListQuery(
        page=1,
        page_size=1,
        protocol=ChannelProtocol.OPENAI_CHAT,
        sort=ChannelSort.NAME,
        direction=SortDirection.DESC,
    ))
    assert [item.id for item in page.items] == ["api:Beta"]
    assert page.total == 1 and page.has_next is False

    with pytest.raises(ManagementError) as caught:
        control.update_channel(
            ADMIN_CONTEXT,
            "api:Alpha",
            ChannelUpdateCommand(enabled=False),
            expected_revision="chrev_stale",
        )
    assert caught.value.code is ManagementErrorCode.REVISION_CONFLICT

    updated = control.update_channel(
        ADMIN_CONTEXT,
        "api:Alpha",
        ChannelUpdateCommand(name="Alpha Renamed", enabled=False, max_concurrent=7),
        expected_revision=alpha.channel.revision,
    ).channel
    assert updated.id == "api:Alpha Renamed"
    assert updated.enabled is False and updated.max_concurrent == 7

    ordered = control.list_channels(ADMIN_CONTEXT, ChannelListQuery())
    revision = control.reorder_channels(
        ADMIN_CONTEXT,
        ("api:Beta", "api:Alpha Renamed"),
        expected_revision=ordered.order_revision,
    )
    assert revision != ordered.order_revision
    assert [item.id for item in control.list_all(ADMIN_CONTEXT)] == [
        "api:Beta", "api:Alpha Renamed",
    ]

    deleted = control.delete_channel(
        ADMIN_CONTEXT, "api:Alpha Renamed", expected_revision=updated.revision,
    )
    assert deleted.deleted is True
    assert registry.get_channel("api:Alpha Renamed") is None
    assert [row["name"] for row in config.get()["channels"]] == ["Beta"]


def test_control_authorizes_read_write_secret_and_destructive_capabilities():
    control = ChannelControl()
    with pytest.raises(ManagementError) as caught:
        control.list_all(_context())
    assert caught.value.code is ManagementErrorCode.CAPABILITY_DENIED

    with pytest.raises(ManagementError) as caught:
        control.create_channel(_context(Capability.WRITE), _command("No Secret Grant"))
    assert caught.value.code is ManagementErrorCode.CAPABILITY_DENIED

    created = control.create_channel(ADMIN_CONTEXT, _command("Delete Grant"))
    with pytest.raises(ManagementError) as caught:
        control.delete_channel(
            _context(Capability.READ, Capability.WRITE),
            created.channel.id,
            expected_revision=created.channel.revision,
        )
    assert caught.value.code is ManagementErrorCode.CAPABILITY_DENIED


def test_delete_uses_registry_cascade_for_cooldown_and_both_affinity_stores():
    control = ChannelControl()
    view = control.create_channel(ADMIN_CONTEXT, _command("Cascade")).channel
    cooldown.record_error(view.id, "model-real", "fixed failure")
    affinity.upsert("server-fingerprint", view.id, "model-real")
    affinity.client_upsert("client-fingerprint", view.id, "model-real")
    assert cooldown.get_state(view.id, "model-real") is not None
    assert affinity.snapshot() and affinity.client_snapshot()

    control.delete_channel(ADMIN_CONTEXT, view.id, expected_revision=view.revision)

    assert cooldown.get_state(view.id, "model-real") is None
    assert all(row["channel_key"] != view.id for row in affinity.snapshot().values())
    assert all(row["channel_key"] != view.id for row in affinity.client_snapshot().values())


def test_existing_and_draft_probe_preserve_adjudicated_cooldown_and_affinity(monkeypatch):
    control = ChannelControl()
    view = control.create_channel(ADMIN_CONTEXT, _command("Probe")).channel
    affinity.upsert("server-fingerprint", view.id, "model-real")
    affinity.client_upsert("client-fingerprint", view.id, "model-real")
    affinity_before = (copy.deepcopy(affinity.snapshot()), copy.deepcopy(affinity.client_snapshot()))

    async def failed(*args, **kwargs):
        return False, 27, "fixed upstream failure"

    monkeypatch.setattr(channel_service.probe, "probe_with_progress", failed)
    before = cooldown.get_state(view.id, "model-real")
    failed_result = asyncio.run(control.probe_existing(
        ADMIN_CONTEXT, view.id, "model-real",
    ))
    assert failed_result.ok is False and failed_result.reason == "fixed upstream failure"
    assert cooldown.get_state(view.id, "model-real") == before
    assert (affinity.snapshot(), affinity.client_snapshot()) == affinity_before

    cooldown.record_error(view.id, "model-real", "old failure")

    async def succeeded(*args, **kwargs):
        return True, 11, None

    monkeypatch.setattr(channel_service.probe, "probe_with_progress", succeeded)
    success_result = asyncio.run(control.probe_existing(
        ADMIN_CONTEXT, view.id, "model-real",
    ))
    assert success_result.ok is True and success_result.cooldown_cleared is True
    assert cooldown.get_state(view.id, "model-real") is None
    assert (affinity.snapshot(), affinity.client_snapshot()) == affinity_before

    monkeypatch.setattr(channel_service.probe, "probe_with_progress", failed)
    draft = DraftProbeCommand(
        name="Draft",
        base_url="https://provider.example.test",
        api_key="sk-fake-channel-key",
        protocol=ChannelProtocol.ANTHROPIC,
        model="model-real",
    )
    draft_result = asyncio.run(control.probe_draft(ADMIN_CONTEXT, draft))
    draft_state = cooldown.get_state("api:Draft__wiz", "model-real")
    assert draft_result.ok is False
    assert draft_state["error_count"] == 1
    assert draft_state["last_error_message"] == "initial probe failed: fixed upstream failure"


def test_model_discovery_uses_catalog_static_fallback_and_does_not_persist():
    control = ChannelControl()
    before = copy.deepcopy(config.get().get("channels", []))
    result = asyncio.run(control.discover_model_ids(
        ADMIN_CONTEXT,
        DiscoveryCommand(
            base_url="https://unused.example.test",
            api_key="sk-fake-channel-key",
            provider_id="kimi",
            provider_preset_id="code",
        ),
    ))
    assert result.source == "static"
    assert result.models
    assert result.error is None and result.retry_available is False
    assert config.get().get("channels", []) == before


def test_clear_actions_report_affected_entries():
    control = ChannelControl()
    one = control.create_channel(ADMIN_CONTEXT, _command("One")).channel
    two = control.create_channel(ADMIN_CONTEXT, _command("Two")).channel
    cooldown.record_error(one.id, "model-real", "one")
    cooldown.record_error(two.id, "model-real", "two")
    affinity.upsert("one-server", one.id, "model-real")
    affinity.client_upsert("one-client", one.id, "model-real")
    affinity.upsert("two-server", two.id, "model-real")

    assert control.clear_channel_errors(ADMIN_CONTEXT, one.id).affected == 1
    assert cooldown.get_state(one.id, "model-real") is None
    assert control.clear_all_errors(ADMIN_CONTEXT).affected == 1
    assert cooldown.active_entries() == []

    assert control.clear_channel_affinity(ADMIN_CONTEXT, one.id).affected == 2
    assert control.clear_all_affinity(ADMIN_CONTEXT).affected == 1
    assert affinity.snapshot() == {} and affinity.client_snapshot() == {}

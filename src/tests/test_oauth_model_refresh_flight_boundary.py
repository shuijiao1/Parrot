from __future__ import annotations

import asyncio
import copy
import threading

import pytest

from src import config, oauth_manager, state_db
from src.openai.codex_constants import CodexConfigurationError


_ACCOUNT = {
    "provider": "openai",
    "type": "openai",
    "email": "flight-boundary@x",
    "workspace_id": "flight-boundary-ws",
    "access_token": "fake-access-token",
    "refresh_token": "fake-refresh-token",
    "expired": "2999-01-01T00:00:00Z",
    "models": ["last-known-good"],
    "disabledModels": [],
}
_INVALID_PROFILE = "../invalid-flight-profile"
_INVALID_PROFILE_ERROR = (
    "openaiOAuth.codexProtocolProfile must be a nonempty profile ID"
)


class _Response:
    status_code = 200
    headers: dict[str, str] = {}

    def __init__(self, models: list[str]):
        self._payload = {
            "models": [
                {"slug": model, "visibility": "list"} for model in models
            ]
        }

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


@pytest.fixture
def refresh_config():
    state_db.init()
    before = copy.deepcopy(config.get())
    valid_provider = copy.deepcopy(before.get("openaiOAuth") or {})
    valid_profile = oauth_manager.codex_protocol_profile(valid_provider)
    account = copy.deepcopy(_ACCOUNT)
    key = oauth_manager.get_account_key(account)
    config.update(lambda cfg: cfg.update(oauthAccounts=[account]))
    try:
        yield key, valid_provider, valid_profile
    finally:
        with oauth_manager._model_discovery_tasks_guard:
            stale = oauth_manager._model_discovery_flights.pop(key, None)
        if stale is not None and not stale.done():
            stale.cancel()
        config.update(lambda cfg: (cfg.clear(), cfg.update(copy.deepcopy(before))))


def _registered_flight(key: str):
    with oauth_manager._model_discovery_tasks_guard:
        return oauth_manager._model_discovery_flights.get(key)


async def _wait_for_thread_event(event: threading.Event) -> None:
    while not event.is_set():
        await asyncio.sleep(0.001)


def _install_token_fake(monkeypatch) -> None:
    async def valid_token(_key: str) -> str:
        return "fake-access-token"

    monkeypatch.setattr(oauth_manager, "mock_mode_enabled", lambda: False)
    monkeypatch.setattr(oauth_manager, "ensure_valid_token", valid_token)


@pytest.mark.asyncio
async def test_invalid_pinned_profile_settles_flight_and_recovers(
    monkeypatch, refresh_config,
):
    key, valid_provider, valid_profile = refresh_config
    _install_token_fake(monkeypatch)
    network_calls = []

    def get_sync(url, **kwargs):
        network_calls.append((url, kwargs))
        return _Response(["recovered-model"])

    monkeypatch.setattr(
        oauth_manager.oauth_model_discovery.network, "get_sync", get_sync,
    )

    def pin_invalid(cfg):
        provider = cfg.setdefault("openaiOAuth", {})
        provider.update({
            "codexProfileAutoUpdate": False,
            "codexCliVersion": valid_profile.client_version,
            "codexProtocolProfile": _INVALID_PROFILE,
        })

    config.update(pin_invalid)
    assert config.get()["openaiOAuth"]["codexProfileAutoUpdate"] is False

    messages = []
    for _attempt in range(2):
        with pytest.raises(CodexConfigurationError) as caught:
            await asyncio.wait_for(
                oauth_manager.refresh_account_models(key), timeout=0.5,
            )
        messages.append(str(caught.value))
        assert _registered_flight(key) is None

    assert messages == [_INVALID_PROFILE_ERROR, _INVALID_PROFILE_ERROR]
    assert network_calls == []

    config.update(
        lambda cfg: cfg.__setitem__("openaiOAuth", copy.deepcopy(valid_provider))
    )
    restored = oauth_manager.codex_protocol_profile()
    assert restored.profile_id == valid_profile.profile_id
    assert restored.client_version == valid_profile.client_version

    result = await asyncio.wait_for(
        oauth_manager.refresh_account_models(key), timeout=1.0,
    )
    assert result["action"] == "updated"
    assert result["new_model_ids"] == ["recovered-model"]
    assert len(network_calls) == 1
    assert _registered_flight(key) is None


@pytest.mark.asyncio
async def test_concurrent_waiter_gets_supplier_error_without_hanging(
    monkeypatch, refresh_config,
):
    key, _valid_provider, _valid_profile = refresh_config
    _install_token_fake(monkeypatch)
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def get_sync(_url, **_kwargs):
        nonlocal calls
        calls += 1
        started.set()
        release.wait(2.0)
        raise RuntimeError("fake upstream failure")

    monkeypatch.setattr(
        oauth_manager.oauth_model_discovery.network, "get_sync", get_sync,
    )
    owner = asyncio.create_task(oauth_manager.refresh_account_models(key))
    waiter = None
    try:
        await asyncio.wait_for(_wait_for_thread_event(started), timeout=1.0)
        waiter = asyncio.create_task(oauth_manager.refresh_account_models(key))
        await asyncio.sleep(0)
        flight = _registered_flight(key)
        assert flight is not None and not flight.done()
        release.set()
        owner_result, waiter_result = await asyncio.wait_for(
            asyncio.gather(owner, waiter), timeout=1.0,
        )
    finally:
        release.set()
        if not owner.done():
            owner.cancel()
        if waiter is not None and not waiter.done():
            waiter.cancel()

    assert owner_result == waiter_result
    assert owner_result["action"] == "error"
    assert owner_result["error"] == "RuntimeError"
    assert calls == 1
    assert oauth_manager.get_account(key)["models"] == ["last-known-good"]
    assert _registered_flight(key) is None


@pytest.mark.asyncio
async def test_concurrent_success_uses_one_supplier_call(
    monkeypatch, refresh_config,
):
    key, _valid_provider, _valid_profile = refresh_config
    _install_token_fake(monkeypatch)
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def get_sync(_url, **_kwargs):
        nonlocal calls
        calls += 1
        started.set()
        release.wait(2.0)
        return _Response(["single-flight-model"])

    monkeypatch.setattr(
        oauth_manager.oauth_model_discovery.network, "get_sync", get_sync,
    )
    owner = asyncio.create_task(oauth_manager.refresh_account_models(key))
    waiter = None
    try:
        await asyncio.wait_for(_wait_for_thread_event(started), timeout=1.0)
        waiter = asyncio.create_task(oauth_manager.refresh_account_models(key))
        await asyncio.sleep(0)
        flight = _registered_flight(key)
        assert flight is not None and not flight.done()
        release.set()
        owner_result, waiter_result = await asyncio.wait_for(
            asyncio.gather(owner, waiter), timeout=1.0,
        )
    finally:
        release.set()
        if not owner.done():
            owner.cancel()
        if waiter is not None and not waiter.done():
            waiter.cancel()

    assert owner_result == waiter_result
    assert owner_result["action"] == "updated"
    assert owner_result["new_model_ids"] == ["single-flight-model"]
    assert calls == 1
    assert _registered_flight(key) is None


@pytest.mark.asyncio
async def test_follower_cancellation_does_not_cancel_shared_flight(
    monkeypatch, refresh_config,
):
    key, _valid_provider, _valid_profile = refresh_config
    _install_token_fake(monkeypatch)
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def get_sync(_url, **_kwargs):
        nonlocal calls
        calls += 1
        started.set()
        release.wait(2.0)
        return _Response(["surviving-flight-model"])

    monkeypatch.setattr(
        oauth_manager.oauth_model_discovery.network, "get_sync", get_sync,
    )
    owner = asyncio.create_task(oauth_manager.refresh_account_models(key))
    cancelled_waiter = None
    surviving_waiter = None
    try:
        await asyncio.wait_for(_wait_for_thread_event(started), timeout=1.0)
        cancelled_waiter = asyncio.create_task(
            oauth_manager.refresh_account_models(key)
        )
        surviving_waiter = asyncio.create_task(
            oauth_manager.refresh_account_models(key)
        )
        await asyncio.sleep(0)
        flight = _registered_flight(key)
        assert flight is not None and not flight.done()

        cancelled_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled_waiter
        assert _registered_flight(key) is flight
        assert not flight.done()
        assert not flight.cancelled()
        assert not owner.done()
        assert not surviving_waiter.done()

        release.set()
        owner_result, waiter_result = await asyncio.wait_for(
            asyncio.gather(owner, surviving_waiter), timeout=1.0,
        )
    finally:
        release.set()
        if not owner.done():
            owner.cancel()
        if cancelled_waiter is not None and not cancelled_waiter.done():
            cancelled_waiter.cancel()
        if surviving_waiter is not None and not surviving_waiter.done():
            surviving_waiter.cancel()

    assert owner_result == waiter_result
    assert owner_result["action"] == "updated"
    assert owner_result["new_model_ids"] == ["surviving-flight-model"]
    assert calls == 1
    assert _registered_flight(key) is None


@pytest.mark.asyncio
async def test_owner_cancellation_propagates_and_cleans_flight(
    monkeypatch, refresh_config,
):
    key, _valid_provider, _valid_profile = refresh_config
    _install_token_fake(monkeypatch)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls = 0

    def get_sync(_url, **_kwargs):
        nonlocal calls
        calls += 1
        started.set()
        release.wait(2.0)
        finished.set()
        return _Response(["must-not-be-persisted"])

    monkeypatch.setattr(
        oauth_manager.oauth_model_discovery.network, "get_sync", get_sync,
    )
    owner = asyncio.create_task(oauth_manager.refresh_account_models(key))
    waiter = None
    try:
        await asyncio.wait_for(_wait_for_thread_event(started), timeout=1.0)
        waiter = asyncio.create_task(oauth_manager.refresh_account_models(key))
        await asyncio.sleep(0)
        flight = _registered_flight(key)
        assert flight is not None and not flight.done()

        owner.cancel()
        await asyncio.sleep(0)
        assert _registered_flight(key) is None
        release.set()
        owner_result, waiter_result = await asyncio.wait_for(
            asyncio.gather(owner, waiter, return_exceptions=True), timeout=1.0,
        )
        await asyncio.wait_for(_wait_for_thread_event(finished), timeout=1.0)
        # Let the executor callback drain; a cancelled owner must not resume
        # catalog persistence after its non-cancellable network thread returns.
        await asyncio.sleep(0.01)
    finally:
        release.set()
        if not owner.done():
            owner.cancel()
        if waiter is not None and not waiter.done():
            waiter.cancel()

    assert isinstance(owner_result, asyncio.CancelledError)
    assert isinstance(waiter_result, asyncio.CancelledError)
    assert calls == 1
    assert oauth_manager.get_account(key)["models"] == ["last-known-good"]
    assert _registered_flight(key) is None

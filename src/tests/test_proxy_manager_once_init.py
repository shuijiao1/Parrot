from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from src.proxy import manager


class _FakeConnector:
    def __init__(self, name: str, marker: str):
        self.name = name
        self.marker = marker
        self.type = "fake"
        self.stats = SimpleNamespace(total_attempts=0)


def _config(marker: str, names: tuple[str, ...]) -> dict:
    return {
        "network": {
            "proxies": {
                name: {"type": "fake", "marker": marker}
                for name in names
            },
            "groups": {f"group-{marker}": list(names)},
            "routing": {
                "default": f"group-{marker}",
                "accounts": {"account": list(names)},
            },
        },
    }


def _isolate_manager(monkeypatch, initial: dict):
    current = {"config": initial}
    callbacks = []
    config_reads = []
    monkeypatch.setattr(manager, "_initialized", False)
    monkeypatch.setattr(manager, "_callback_registered", False)
    monkeypatch.setattr(manager, "_config_generation", None)
    monkeypatch.setattr(manager, "_snapshot", manager._EMPTY_SNAPSHOT)

    def get_config():
        config_reads.append(current["config"])
        return current["config"]

    monkeypatch.setattr(manager.config, "get", get_config)
    monkeypatch.setattr(manager.config, "on_reload", callbacks.append)
    return current, callbacks, config_reads


def test_init_rebuilds_once_per_generation_and_reload_is_immediately_visible(monkeypatch):
    first = _config("first", ("p1",))
    second = _config("second", ("p1", "p2"))
    current, callbacks, config_reads = _isolate_manager(monkeypatch, first)
    builds = []
    real_build = manager._build_snapshot

    def counted_build(cfg, previous):
        builds.append(cfg)
        return real_build(cfg, previous)

    monkeypatch.setattr(manager, "_build_snapshot", counted_build)
    monkeypatch.setattr(
        manager,
        "connector_from_config",
        lambda name, cfg: _FakeConnector(name, cfg["marker"]),
    )

    for _ in range(100):
        manager.init()

    assert builds == [first]
    assert config_reads == [first] * 100
    assert callbacks == [manager._on_config_reload]
    old_connector = manager.get_connector("p1")
    old_connector.stats.total_attempts = 7
    assert manager.resolve_proxy_chain(account_key="account") == ["p1"]

    current["config"] = second
    callbacks[0](second)

    assert builds == [first, second]
    assert config_reads == ([first] * 100) + [second]
    assert manager.get_connector("p1") is not old_connector
    assert manager.get_connector("p1").stats is old_connector.stats
    assert manager.get_connector("p1").stats.total_attempts == 7
    assert manager.get_connector("p2").marker == "second"
    assert manager.get_group("group-second") == ["p1", "p2"]
    assert manager.resolve_proxy_chain(account_key="account") == ["p1", "p2"]

    for _ in range(100):
        manager.init()
    assert builds == [first, second]
    assert config_reads == ([first] * 100) + ([second] * 101)
    assert callbacks == [manager._on_config_reload]

    # Public copies cannot mutate the immutable generation held by the manager.
    groups = manager.all_groups()
    routing = manager.get_routing()
    groups["group-second"].append("injected")
    routing["accounts"]["account"].append("injected")
    assert manager.get_group("group-second") == ["p1", "p2"]
    assert manager.resolve_proxy_chain(account_key="account") == ["p1", "p2"]


def test_repeated_init_detects_external_config_replacement_without_rebuilding_stable_generation(
    monkeypatch, tmp_path,
):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(_config("first", ("p1",))), encoding="utf-8")

    monkeypatch.setattr(manager.config, "CONFIG_PATH", str(path))
    monkeypatch.setattr(manager.config, "_cache", None)
    monkeypatch.setattr(manager.config, "_mtime", 0.0)
    monkeypatch.setattr(manager.config, "_reload_callbacks", [])
    monkeypatch.setattr(manager, "_initialized", False)
    monkeypatch.setattr(manager, "_callback_registered", False)
    monkeypatch.setattr(manager, "_config_generation", None)
    monkeypatch.setattr(manager, "_snapshot", manager._EMPTY_SNAPSHOT)
    monkeypatch.setattr(
        manager,
        "connector_from_config",
        lambda name, cfg: _FakeConnector(name, cfg["marker"]),
    )
    builds = []
    real_build = manager._build_snapshot

    def counted_build(cfg, previous):
        builds.append(cfg)
        return real_build(cfg, previous)

    monkeypatch.setattr(manager, "_build_snapshot", counted_build)
    manager.init()
    first_snapshot = manager._snapshot
    assert manager.resolve_proxy_chain(account_key="account") == ["p1"]

    replacement = tmp_path / "replacement.json"
    replacement.write_text(
        json.dumps(_config("second", ("p1", "p2"))), encoding="utf-8",
    )
    current_mtime_ns = path.stat().st_mtime_ns
    os.utime(replacement, ns=(current_mtime_ns + 2_000_000_000,) * 2)
    os.replace(replacement, path)

    # No explicit config.reload/update and no manual callback: init() itself must
    # retain the baseline mtime-poll trigger while generation identity avoids work.
    manager.init()
    second_snapshot = manager._snapshot
    assert second_snapshot is not first_snapshot
    assert manager.resolve_proxy_chain(account_key="account") == ["p1", "p2"]
    assert manager.get_connector("p2").marker == "second"
    assert len(builds) == 2

    manager.init()
    assert manager._snapshot is second_snapshot
    assert len(builds) == 2


def test_concurrent_first_init_registers_and_builds_once(monkeypatch):
    cfg = _config("only", ("p1", "p2", "p3"))
    _current, callbacks, config_reads = _isolate_manager(monkeypatch, cfg)
    build_count = 0
    build_count_lock = threading.Lock()
    real_build = manager._build_snapshot

    def counted_build(current_cfg, previous):
        nonlocal build_count
        with build_count_lock:
            build_count += 1
        # Widen the race: every other init must still wait and fast-return.
        time.sleep(0.02)
        return real_build(current_cfg, previous)

    monkeypatch.setattr(manager, "_build_snapshot", counted_build)
    monkeypatch.setattr(
        manager,
        "connector_from_config",
        lambda name, proxy_cfg: _FakeConnector(name, proxy_cfg["marker"]),
    )
    barrier = threading.Barrier(24)

    def initialize():
        barrier.wait()
        manager.init()

    with ThreadPoolExecutor(max_workers=24) as pool:
        futures = [pool.submit(initialize) for _ in range(24)]
        for future in futures:
            future.result(timeout=5)

    assert build_count == 1
    assert config_reads == [cfg] * 24
    assert callbacks == [manager._on_config_reload]
    assert list(manager.all_connectors()) == ["p1", "p2", "p3", "direct"]
    assert manager.get_group("group-only") == ["p1", "p2", "p3"]


def test_reload_publishes_only_a_complete_snapshot(monkeypatch):
    first = _config("old", ("old-a", "old-b"))
    second = _config("new", ("new-a", "new-b"))
    current, callbacks, _config_reads = _isolate_manager(monkeypatch, first)
    build_started = threading.Event()
    allow_build = threading.Event()

    def blocking_factory(name, cfg):
        if cfg["marker"] == "new" and name == "new-a":
            build_started.set()
            assert allow_build.wait(timeout=5)
        return _FakeConnector(name, cfg["marker"])

    monkeypatch.setattr(manager, "connector_from_config", blocking_factory)
    manager.init()
    old_snapshot = manager._snapshot
    assert list(old_snapshot.connectors) == ["old-a", "old-b"]

    current["config"] = second
    with ThreadPoolExecutor(max_workers=1) as pool:
        reload_future = pool.submit(callbacks[0], second)
        assert build_started.wait(timeout=5)

        # Building uses locals; the single published pointer remains the complete
        # old generation until every connector/group/route in the new one is ready.
        assert manager._snapshot is old_snapshot
        assert list(manager._snapshot.connectors) == ["old-a", "old-b"]

        allow_build.set()
        reload_future.result(timeout=5)
    assert manager._snapshot is not old_snapshot
    assert list(manager.all_connectors()) == ["new-a", "new-b", "direct"]
    assert manager.get_group("group-new") == ["new-a", "new-b"]
    assert manager.get_routing() == {
        "default": "group-new",
        "accounts": {"account": ["new-a", "new-b"]},
    }

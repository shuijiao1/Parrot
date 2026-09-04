from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path

import pytest

from src import state_cow
from src.state_store import RUNTIME_DOMAINS, StateStore


def _store(tmp_path, *, disable_timer: bool = True) -> StateStore:
    store = StateStore(str(tmp_path / "runtime.json"), str(tmp_path / "durable.json"))
    store.start()
    if disable_timer:
        store._schedule_runtime_flush = lambda: None
    return store


def test_single_runtime_mutation_copies_only_changed_domain_and_record(tmp_path, monkeypatch):
    store = _store(tmp_path)
    source = {"nested": {"value": 1}}
    store._mutate("performance_stats", lambda domain: domain.__setitem__("target", source))
    store._mutate("performance_stats", lambda domain: domain.__setitem__("unrelated", {"value": 2}))
    store._mutate("channel_errors", lambda domain: domain.__setitem__("other", {"value": 3}))

    with store._lock:
        before_domains = dict(store._data)
        before_target = store._data["performance_stats"]["target"]
        before_unrelated = store._data["performance_stats"]["unrelated"]

    full_encodes = 0
    real_payload_bytes = StateStore._payload_bytes

    def counted_payload_bytes(payload):
        nonlocal full_encodes
        full_encodes += 1
        return real_payload_bytes(payload)

    monkeypatch.setattr(StateStore, "_payload_bytes", staticmethod(counted_payload_bytes))

    def update(domain):
        row = domain["target"]
        row["nested"]["value"] = 4
        return row

    result = store._mutate("performance_stats", update)
    assert full_encodes == 0
    with store._lock:
        assert store._data["performance_stats"] is not before_domains["performance_stats"]
        assert store._data["performance_stats"]["target"] is not before_target
        assert store._data["performance_stats"]["unrelated"] is before_unrelated
        assert all(
            store._data[domain] is before_domains[domain]
            for domain in RUNTIME_DOMAINS
            if domain != "performance_stats"
        )
    assert before_target == {"nested": {"value": 1}}
    assert store.get("performance_stats", "target") == {"nested": {"value": 4}}

    # Neither the original input nor the callback result is an alias of the
    # committed record.
    source["nested"]["value"] = 8
    result["nested"]["value"] = 9
    assert store.get("performance_stats", "target") == {"nested": {"value": 4}}
    store.close()


def test_large_unrelated_domains_are_not_copied_or_fully_encoded(tmp_path, monkeypatch):
    store = _store(tmp_path)
    large = {f"key-{index}": {"blob": "x" * 128, "index": index} for index in range(1000)}
    with store._lock:
        for domain in RUNTIME_DOMAINS:
            if domain != "performance_stats":
                store._data[domain] = large.copy()
        store._data["performance_stats"] = {"target": {"value": 0}}
        before_domains = dict(store._data)

    copied_records = 0
    real_deepcopy = state_cow.copy.deepcopy

    def counted_deepcopy(value):
        nonlocal copied_records
        if isinstance(value, dict):
            copied_records += 1
        return real_deepcopy(value)

    monkeypatch.setattr(state_cow.copy, "deepcopy", counted_deepcopy)
    monkeypatch.setattr(
        StateStore,
        "_payload_bytes",
        staticmethod(lambda _payload: pytest.fail("full runtime payload encoded during mutation")),
    )
    store._mutate("performance_stats", lambda domain: domain.__setitem__("target", {"value": 1}))

    assert copied_records == 1
    with store._lock:
        assert store._data["performance_stats"] is not before_domains["performance_stats"]
        assert all(
            store._data[domain] is before_domains[domain]
            for domain in RUNTIME_DOMAINS
            if domain != "performance_stats"
        )
        store._dirty["runtime"] = False
    store.close()


@pytest.mark.parametrize(
    "bad",
    [object(), float("nan"), float("inf"), float("-inf"), (1, 2), {1: "lossy"}, "\ud800"],
)
def test_runtime_rejects_touched_non_json_record_before_publication(tmp_path, bad):
    store = _store(tmp_path)
    generation = store.health()["generation"]["runtime"]
    with pytest.raises((TypeError, ValueError)):
        store._mutate(
            "performance_stats",
            lambda domain: domain.__setitem__("bad", {"nested": [bad]}),
        )
    assert store.get("performance_stats", "bad") is None
    assert store.health()["generation"]["runtime"] == generation
    store.close()


def test_narrow_validation_now_and_complete_encoding_at_flush(tmp_path, monkeypatch):
    store = _store(tmp_path)
    narrow_shapes = []
    real_dumps = state_cow.json.dumps
    real_payload_bytes = StateStore._payload_bytes
    complete_encodes = 0

    def counted_narrow(value, *args, **kwargs):
        narrow_shapes.append(copy.deepcopy(value))
        return real_dumps(value, *args, **kwargs)

    def counted_complete(payload):
        nonlocal complete_encodes
        complete_encodes += 1
        return real_payload_bytes(payload)

    monkeypatch.setattr(state_cow.json, "dumps", counted_narrow)
    monkeypatch.setattr(StateStore, "_payload_bytes", staticmethod(counted_complete))
    store._mutate("performance_stats", lambda domain: domain.__setitem__("one", {"value": 1}))
    assert narrow_shapes == [{"one": {"value": 1}}]
    assert complete_encodes == 0

    store.flush("runtime", strict=True)
    assert complete_encodes > 0
    generation, payload = StateStore.read_snapshot(str(tmp_path / "runtime.json"), "runtime")
    assert generation == store.health()["generation"]["runtime"]
    assert payload["performance_stats"]["one"] == {"value": 1}
    store.close()


def test_mutate_many_is_atomic_and_copies_only_participating_domains(tmp_path):
    store = _store(tmp_path)
    store._mutate("performance_stats", lambda domain: domain.__setitem__("old", {"value": 1}))
    store._mutate("channel_errors", lambda domain: domain.__setitem__("old", {"value": 1}))
    store._mutate("cache_affinities", lambda domain: domain.__setitem__("keep", {"value": 1}))
    with store._lock:
        before_domains = dict(store._data)
        old_performance = store._data["performance_stats"]["old"]
        old_errors = store._data["channel_errors"]["old"]
    before_generation = store.health()["generation"]["runtime"]

    def rename(data):
        performance = data["performance_stats"].pop("old")
        errors = data["channel_errors"].pop("old")
        performance["value"] = 2
        errors["value"] = 2
        data["performance_stats"]["new"] = performance
        data["channel_errors"]["new"] = errors
        return {"moved": 2}

    assert store._mutate_many(("performance_stats", "channel_errors"), rename) == {"moved": 2}
    assert store.health()["generation"]["runtime"] == before_generation + 1
    assert old_performance == {"value": 1} and old_errors == {"value": 1}
    assert store.get("performance_stats", "new") == {"value": 2}
    assert store.get("channel_errors", "new") == {"value": 2}
    with store._lock:
        assert store._data["performance_stats"] is not before_domains["performance_stats"]
        assert store._data["channel_errors"] is not before_domains["channel_errors"]
        assert store._data["cache_affinities"] is before_domains["cache_affinities"]
    store.close()


def test_mutate_many_invalid_second_domain_rolls_back_every_domain(tmp_path):
    store = _store(tmp_path)
    store._mutate("performance_stats", lambda domain: domain.__setitem__("one", {"value": 1}))
    store._mutate("channel_errors", lambda domain: domain.__setitem__("one", {"value": 1}))
    before = store.health()["generation"]["runtime"]

    def invalid(data):
        data["performance_stats"]["one"]["value"] = 2
        data["channel_errors"]["one"]["value"] = float("nan")

    with pytest.raises(ValueError):
        store._mutate_many(("performance_stats", "channel_errors"), invalid)
    assert store.get("performance_stats", "one") == {"value": 1}
    assert store.get("channel_errors", "one") == {"value": 1}
    assert store.health()["generation"]["runtime"] == before
    store.close()


def test_get_items_and_values_cannot_pollute_publication(tmp_path):
    store = _store(tmp_path)
    source = {"nested": {"value": 1}}
    store._mutate("performance_stats", lambda domain: domain.__setitem__("one", source))
    source["nested"]["value"] = 2
    row = store.get("performance_stats", "one")
    items = store.items("performance_stats")
    values = store.values("performance_stats")
    row["nested"]["value"] = 3
    items["one"]["nested"]["value"] = 4
    values[0]["nested"]["value"] = 5
    assert store.get("performance_stats", "one") == {"nested": {"value": 1}}
    store.close()


def test_concurrent_reader_never_observes_torn_mutate_many_publication(tmp_path):
    store = _store(tmp_path)
    store._mutate_many(
        ("performance_stats", "channel_errors"),
        lambda data: (
            data["performance_stats"].__setitem__("pair", {"version": 0}),
            data["channel_errors"].__setitem__("pair", {"version": 0}),
        ),
    )
    stopped = threading.Event()
    failures = []

    def reader():
        while not stopped.is_set():
            with store._lock:
                left = store._data["performance_stats"]["pair"]["version"]
                right = store._data["channel_errors"]["pair"]["version"]
            if left != right:
                failures.append((left, right))
                stopped.set()

    readers = [threading.Thread(target=reader) for _ in range(4)]
    for thread in readers:
        thread.start()
    for version in range(1, 201):
        store._mutate_many(
            ("performance_stats", "channel_errors"),
            lambda data, version=version: (
                data["performance_stats"].__setitem__("pair", {"version": version}),
                data["channel_errors"].__setitem__("pair", {"version": version}),
            ),
        )
    stopped.set()
    for thread in readers:
        thread.join(5)
    assert not failures
    assert all(not thread.is_alive() for thread in readers)
    store.close()


def test_debounce_flush_persists_complete_compatible_snapshot(tmp_path, monkeypatch):
    store = _store(tmp_path, disable_timer=False)
    store._debounce_seconds = 0.02
    written = threading.Event()
    real_write = store.write_snapshot

    def observed_write(path, kind, generation, payload, **kwargs):
        result = real_write(path, kind, generation, payload, **kwargs)
        if kind == "runtime":
            written.set()
        return result

    monkeypatch.setattr(store, "write_snapshot", observed_write)
    store._mutate("cache_affinities", lambda domain: domain.__setitem__("fp", {"value": 7}))
    assert written.wait(5)
    assert store.health()["dirty"]["runtime"] is False
    raw = json.loads(Path(tmp_path / "runtime.json").read_text())
    assert set(raw) == {"schema", "version", "kind", "generation", "checksum", "payload"}
    assert tuple(raw["payload"]) == tuple(sorted(RUNTIME_DOMAINS))
    assert raw["payload"]["cache_affinities"]["fp"] == {"value": 7}
    store.close()


def test_failed_deferred_flush_keeps_last_disk_snapshot_then_retries(tmp_path, monkeypatch):
    store = _store(tmp_path)
    store._mutate("performance_stats", lambda domain: domain.__setitem__("old", {"value": 1}))
    store.flush("runtime", strict=True)
    before = Path(tmp_path / "runtime.json").read_bytes()
    store._mutate("performance_stats", lambda domain: domain.__setitem__("new", {"value": 2}))
    real_write = store.write_snapshot
    monkeypatch.setattr(
        store,
        "write_snapshot",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected write failure")),
    )
    assert store.flush("runtime", strict=False) is False
    assert store.health()["dirty"]["runtime"] is True
    assert Path(tmp_path / "runtime.json").read_bytes() == before

    monkeypatch.setattr(store, "write_snapshot", real_write)
    assert store.flush("runtime", strict=True) is True
    store.close()
    restored = StateStore(str(tmp_path / "runtime.json"), str(tmp_path / "durable.json"))
    restored.start()
    assert restored.get("performance_stats", "old") == {"value": 1}
    assert restored.get("performance_stats", "new") == {"value": 2}
    restored.close()


def test_close_flushes_runtime_and_old_snapshot_load_remains_compatible(tmp_path):
    runtime = str(tmp_path / "runtime.json")
    durable = str(tmp_path / "durable.json")
    old_payload = {domain: {} for domain in RUNTIME_DOMAINS}
    old_payload["channel_errors"] = {"old": {"value": 1}}
    StateStore.write_snapshot(runtime, "runtime", 9, old_payload)

    store = StateStore(runtime, durable)
    store.start()
    assert store.get("channel_errors", "old") == {"value": 1}
    store._schedule_runtime_flush = lambda: None
    store._mutate("channel_errors", lambda domain: domain.__setitem__("new", {"value": 2}))
    assert store.close() is True

    restored = StateStore(runtime, durable)
    restored.start()
    assert restored.health()["generation"]["runtime"] == 10
    assert restored.items("channel_errors") == {
        "old": {"value": 1},
        "new": {"value": 2},
    }
    restored.close()

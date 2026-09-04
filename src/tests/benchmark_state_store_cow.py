"""Reproducible isolated benchmark for PERF-02 StateStore mutation cost.

Run from the repository root (it only creates snapshots under a TemporaryDirectory):

    PYTHONPATH=. env -u PARROT_NO_REFRESH PYTHONDONTWRITEBYTECODE=1 \
      /disk/parrot-webui/venv/bin/python src/tests/benchmark_state_store_cow.py

The workload puts 2,000 records in each of all eight runtime domains, disables
the debounce timer during the timed section, and repeatedly replaces one
``performance_stats`` record.  It reports stable repeated timings, complete
payload encoding calls, CowDomain record deep copies, and publication identity
changes.  The same workload was run before this change at baseline
b0c2895e5c8d866d937ec4ffa8a85216ac342d50 (using its then-current mutation
implementation) for the before/after comparison in the delivery report.
"""
from __future__ import annotations

import gc
import json
import statistics
import tempfile
import time
from pathlib import Path

from src import state_cow
from src.state_store import RUNTIME_DOMAINS, StateStore

RECORDS_PER_DOMAIN = 2_000
BLOB_BYTES = 256
OPS_PER_REPEAT = 20
REPEATS = 7


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="parrot-state-cow-benchmark-") as directory:
        store = StateStore(
            str(Path(directory) / "runtime.json"),
            str(Path(directory) / "durable.json"),
        )
        store.start()
        large = {
            f"key-{index}": {"index": index, "blob": "x" * BLOB_BYTES}
            for index in range(RECORDS_PER_DOMAIN)
        }
        with store._lock:
            for domain in RUNTIME_DOMAINS:
                store._data[domain] = large.copy()
            store._data["performance_stats"]["target"] = {"value": 0}
            initial_domains = dict(store._data)
            unaffected_record = store._data["performance_stats"]["key-0"]
        store._schedule_runtime_flush = lambda: None

        complete_payload_encodes = 0
        cow_record_deepcopies = 0
        real_payload_bytes = StateStore._payload_bytes
        real_deepcopy = state_cow.copy.deepcopy

        def counted_payload_bytes(payload):
            nonlocal complete_payload_encodes
            complete_payload_encodes += 1
            return real_payload_bytes(payload)

        def counted_deepcopy(value):
            nonlocal cow_record_deepcopies
            if isinstance(value, dict):
                cow_record_deepcopies += 1
            return real_deepcopy(value)

        StateStore._payload_bytes = staticmethod(counted_payload_bytes)
        state_cow.copy.deepcopy = counted_deepcopy
        samples: list[float] = []
        try:
            for _repeat in range(REPEATS):
                gc.collect()
                started = time.perf_counter()
                for index in range(OPS_PER_REPEAT):
                    store._mutate(
                        "performance_stats",
                        lambda domain, index=index: domain.__setitem__(
                            "target", {"value": index},
                        ),
                    )
                samples.append((time.perf_counter() - started) / OPS_PER_REPEAT)
        finally:
            StateStore._payload_bytes = staticmethod(real_payload_bytes)
            state_cow.copy.deepcopy = real_deepcopy

        with store._lock:
            changed_domains = [
                domain for domain in RUNTIME_DOMAINS
                if store._data[domain] is not initial_domains[domain]
            ]
            unaffected_record_reused = (
                store._data["performance_stats"]["key-0"] is unaffected_record
            )
            store._dirty["runtime"] = False
        store.close()

        approximate_runtime_json_bytes = len(json.dumps(
            {domain: large for domain in RUNTIME_DOMAINS},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8"))
        operations = OPS_PER_REPEAT * REPEATS
        print(json.dumps({
            "records_per_domain": RECORDS_PER_DOMAIN,
            "runtime_domains": len(RUNTIME_DOMAINS),
            "approximate_runtime_json_bytes": approximate_runtime_json_bytes,
            "ops_per_repeat": OPS_PER_REPEAT,
            "repeats": REPEATS,
            "seconds_per_op": samples,
            "median_seconds_per_op": statistics.median(samples),
            "min_seconds_per_op": min(samples),
            "complete_payload_encodes_per_op": complete_payload_encodes / operations,
            "cow_record_deepcopies_per_op": cow_record_deepcopies / operations,
            "changed_domain_publications": changed_domains,
            "unaffected_record_reused": unaffected_record_reused,
        }, indent=2))


if __name__ == "__main__":
    main()

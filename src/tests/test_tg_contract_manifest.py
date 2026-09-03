"""Cross-segment gate for the frozen v0.31.13 Telegram contract manifest."""

from __future__ import annotations

import re
from pathlib import Path

from src.tests.tg_contract import (
    assert_capability_coverage,
    assert_strict_equal,
    load_jsonl,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = Path(__file__).parent / "fixtures/tg_contract/v0.31.13"
MANIFEST = FIXTURE_ROOT / "manifest.jsonl"
SEGMENT_ROOT = FIXTURE_ROOT / "segments"
DOC = ROOT / "docs/13-management-control-api-refactor.md"

SEGMENT_CAPABILITIES = {
    "core": {f"TG-CORE-{number:02d}" for number in range(1, 7)},
    "main_status": {"TG-MAIN-01", "TG-HELP-01", "TG-STATUS-01"},
    "oauth": {
        *(f"TG-OA-{number:02d}" for number in range(1, 8)),
        "TG-ODM-01",
        "TG-OA-SET-01",
    },
    "channels_apikey": {
        *(f"TG-CH-{number:02d}" for number in range(1, 6)),
        *(f"TG-AK-{number:02d}" for number in range(1, 5)),
    },
    "observability": {
        "TG-CACHE-01",
        "TG-STATS-01",
        "TG-STATS-02",
        *(f"TG-LOG-{number:02d}" for number in range(1, 5)),
        "TG-MEDIA-01",
    },
    "system": {f"TG-SYS-{number:02d}" for number in range(1, 9)},
    "model_routing": {
        "TG-MAP-01",
        "TG-MAP-02",
        "TG-LB-01",
        "TG-PX-01",
        "TG-PX-02",
    },
    "auxiliary": {
        "TG-TL-01",
        "TG-STAT-01",
        "TG-UPD-01",
        "TG-IMG-01",
        "TG-XIM-01",
    },
}
SEGMENT_ORDER = tuple(SEGMENT_CAPABILITIES)
EXPECTED_CAPABILITIES = set().union(*SEGMENT_CAPABILITIES.values())
EXPECTED_CASE_COUNT = 663


def _doc_capabilities() -> set[str]:
    text = DOC.read_text(encoding="utf-8")
    section = text.split("## 14. Telegram 零变化完整功能清单", 1)[1]
    section = section.split("### 14.6 基线轨迹格式", 1)[0]
    return set(re.findall(r"TG-[A-Z]+(?:-[A-Z]+)*-\d{2}", section))


def test_final_manifest_is_exact_stable_concatenation_of_all_segments():
    paths = [SEGMENT_ROOT / f"{name}.jsonl" for name in SEGMENT_ORDER]
    assert {path.name for path in SEGMENT_ROOT.glob("*.jsonl")} == {
        path.name for path in paths
    }
    expected_bytes = b"".join(path.read_bytes() for path in paths)
    assert all(path.read_bytes().endswith(b"\n") for path in paths)
    assert MANIFEST.read_bytes() == expected_bytes

    expected_cases = [case for path in paths for case in load_jsonl(path)]
    manifest_cases = load_jsonl(MANIFEST)
    assert_strict_equal(expected_cases, manifest_cases)
    assert len(manifest_cases) == EXPECTED_CASE_COUNT
    assert len({case["caseId"] for case in manifest_cases}) == EXPECTED_CASE_COUNT


def test_manifest_capabilities_match_doc_and_segment_ownership_bidirectionally():
    assert len(EXPECTED_CAPABILITIES) == 53
    assert EXPECTED_CAPABILITIES == _doc_capabilities()
    manifest_cases = load_jsonl(MANIFEST)
    assert_capability_coverage(EXPECTED_CAPABILITIES, manifest_cases)

    for name, expected_ids in SEGMENT_CAPABILITIES.items():
        assert_capability_coverage(
            expected_ids,
            load_jsonl(SEGMENT_ROOT / f"{name}.jsonl"),
        )


def test_frozen_manifest_has_no_management_auth_surface_or_update_mode():
    manifest_text = MANIFEST.read_text(encoding="utf-8")
    assert "mauth:" not in manifest_text
    source_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(__file__).parent.glob("test_tg_contract_*.py")
    )
    forbidden = "TG_CONTRACT_" + "RECORD"
    assert forbidden not in source_text
    assert re.search(
        r"(?:SEGMENT|MANIFEST)\.write_(?:text|bytes)\s*\(", source_text
    ) is None
    assert re.search(
        r"open\s*\(\s*(?:SEGMENT|MANIFEST)[^\n]*['\"]w", source_text
    ) is None

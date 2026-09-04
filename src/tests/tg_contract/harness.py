"""Small capture/schema/replay harness for Telegram JSONL contract segments.

The comparator deliberately has no normalization or ignore mechanism.  In
particular, strings are compared as UTF-8 bytes and dictionaries must have the
same keys.  Lists therefore preserve both Telegram call order and keyboard
row/column order.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


CORE_CAPABILITY_IDS = frozenset({f"TG-CORE-{number:02d}" for number in range(1, 7)})
_REQUIRED_CASE_KEYS = frozenset({
    "caseId",
    "capabilityId",
    "entry",
    "initialConfig",
    "initialState",
    "initialRuntime",
    "tgApi",
    "stateSteps",
    "finalBusinessState",
    "expectedException",
})
_REQUIRED_TG_CALL_KEYS = frozenset({"method", "payload"})


class JsonlContractError(AssertionError):
    """A segment does not conform to the Telegram trace schema."""


class StrictMismatch(AssertionError):
    """Expected and actual traces differ without normalization."""


def _type_name(value: Any) -> str:
    return type(value).__name__


def assert_strict_equal(expected: Any, actual: Any, path: str = "$") -> None:
    """Recursively compare raw JSON structures, including exact scalar types.

    Python normally considers ``True == 1``.  That is not acceptable here:
    Telegram payload booleans, numbers, absent fields, and null are distinct.
    Strings are encoded to UTF-8 before comparison so every newline, NBSP,
    emoji, HTML byte, and escape-sensitive character remains significant.
    """
    if type(expected) is not type(actual):
        raise StrictMismatch(
            f"{path}: type differs: expected {_type_name(expected)}, "
            f"actual {_type_name(actual)}"
        )
    if isinstance(expected, dict):
        expected_keys = list(expected.keys())
        actual_keys = list(actual.keys())
        if set(expected_keys) != set(actual_keys):
            missing = sorted(set(expected_keys) - set(actual_keys))
            extra = sorted(set(actual_keys) - set(expected_keys))
            raise StrictMismatch(f"{path}: object keys differ: missing={missing}, extra={extra}")
        if expected_keys != actual_keys:
            raise StrictMismatch(
                f"{path}: object key order differs: "
                f"expected {expected_keys!r}, actual {actual_keys!r}"
            )
        for key in expected_keys:
            assert_strict_equal(expected[key], actual[key], f"{path}.{key}")
        return
    if isinstance(expected, list):
        if len(expected) != len(actual):
            raise StrictMismatch(
                f"{path}: list length differs: expected {len(expected)}, actual {len(actual)}"
            )
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            assert_strict_equal(expected_item, actual_item, f"{path}[{index}]")
        return
    if isinstance(expected, str):
        expected_bytes = expected.encode("utf-8")
        actual_bytes = actual.encode("utf-8")
        if expected_bytes != actual_bytes:
            raise StrictMismatch(
                f"{path}: UTF-8 bytes differ: expected {expected_bytes!r}, actual {actual_bytes!r}"
            )
        return
    if expected != actual:
        raise StrictMismatch(f"{path}: expected {expected!r}, actual {actual!r}")


def _expect_type(case_id: str, field: str, value: Any, expected_type: type) -> None:
    if type(value) is not expected_type:
        raise JsonlContractError(
            f"{case_id}: {field} must be {expected_type.__name__}, got {_type_name(value)}"
        )


def validate_case(case: Any, *, line_number: int | None = None) -> dict[str, Any]:
    location = f"line {line_number}" if line_number is not None else "case"
    if type(case) is not dict:
        raise JsonlContractError(f"{location}: top level must be an object")
    keys = set(case)
    if keys != _REQUIRED_CASE_KEYS:
        missing = sorted(_REQUIRED_CASE_KEYS - keys)
        extra = sorted(keys - _REQUIRED_CASE_KEYS)
        raise JsonlContractError(f"{location}: case keys differ: missing={missing}, extra={extra}")

    case_id = case["caseId"]
    _expect_type(location, "caseId", case_id, str)
    if not case_id:
        raise JsonlContractError(f"{location}: caseId must not be empty")
    _expect_type(case_id, "capabilityId", case["capabilityId"], str)
    if not case_id.startswith(case["capabilityId"] + "."):
        raise JsonlContractError(f"{case_id}: caseId must begin with capabilityId plus '.'")
    for field in ("entry", "initialConfig", "initialState", "initialRuntime", "finalBusinessState"):
        _expect_type(case_id, field, case[field], dict)
    for field in ("tgApi", "stateSteps"):
        _expect_type(case_id, field, case[field], list)
    exception = case["expectedException"]
    if exception is not None and type(exception) is not dict:
        raise JsonlContractError(f"{case_id}: expectedException must be object or null")
    if type(exception) is dict and set(exception) != {"type", "message"}:
        raise JsonlContractError(f"{case_id}: expectedException keys must be type and message")

    for index, call in enumerate(case["tgApi"]):
        if type(call) is not dict or set(call) != _REQUIRED_TG_CALL_KEYS:
            raise JsonlContractError(
                f"{case_id}: tgApi[{index}] must have exactly method and payload"
            )
        _expect_type(case_id, f"tgApi[{index}].method", call["method"], str)
        _expect_type(case_id, f"tgApi[{index}].payload", call["payload"], dict)
    for index, step in enumerate(case["stateSteps"]):
        _expect_type(case_id, f"stateSteps[{index}]", step, dict)
    return case


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Load and validate one segment while rejecting blank lines and duplicates."""
    segment_path = Path(path)
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    raw_lines = segment_path.read_text(encoding="utf-8").splitlines()
    if not raw_lines:
        raise JsonlContractError(f"{segment_path}: segment is empty")
    for line_number, raw in enumerate(raw_lines, 1):
        if raw == "":
            raise JsonlContractError(f"{segment_path}: blank JSONL line {line_number}")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JsonlContractError(
                f"{segment_path}: invalid JSON on line {line_number}: {exc.msg}"
            ) from exc
        case = validate_case(parsed, line_number=line_number)
        case_id = case["caseId"]
        if case_id in seen:
            raise JsonlContractError(f"{segment_path}: duplicate caseId {case_id!r}")
        seen.add(case_id)
        cases.append(case)
    return cases


def assert_capability_coverage(
    expected_ids: Iterable[str], cases: Sequence[Mapping[str, Any]]
) -> None:
    """Require bidirectional equality, not a subset check."""
    expected = set(expected_ids)
    actual = {str(case["capabilityId"]) for case in cases}
    if expected != actual:
        raise JsonlContractError(
            f"capability coverage differs: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


class TraceCapture:
    """Capture ordered Telegram API method/payload pairs without altering data."""

    def __init__(self, responses: Mapping[str, Any] | None = None):
        self.calls: list[dict[str, Any]] = []
        self.responses = deepcopy(dict(responses or {}))

    def api(self, method: str, data: dict[str, Any] | None = None) -> Any:
        payload = {} if data is None else deepcopy(data)
        self.calls.append({"method": method, "payload": payload})
        response = self.responses.get(method, {"ok": True, "result": {}})
        if isinstance(response, list):
            if not response:
                raise AssertionError(f"no fake response left for {method}")
            return deepcopy(response.pop(0))
        if isinstance(response, BaseException):
            raise response
        return deepcopy(response)

    def record(self, method: str, payload: dict[str, Any]) -> None:
        self.calls.append({"method": method, "payload": deepcopy(payload)})


def replay_and_compare(
    expected_calls: Sequence[Mapping[str, Any]],
    invoke: Callable[[str, dict[str, Any]], Any],
) -> None:
    """Replay captured calls into a fake target and compare what it receives."""
    replayed: list[dict[str, Any]] = []
    for call in expected_calls:
        method = call["method"]
        payload = deepcopy(call["payload"])
        invoke(method, payload)
        replayed.append({"method": method, "payload": payload})
    assert_strict_equal(list(expected_calls), replayed)

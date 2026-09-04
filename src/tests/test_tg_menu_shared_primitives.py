from __future__ import annotations

import math

import pytest

from src import (
    model_metadata,
    notifier,
    oauth_errors,
    oauth_ids,
    status_monitor,
    update_checker,
)
from src.management_control.oauth import menu_bridge
from src.oauth import antigravity
from src.telegram.menus import (
    apikey_menu,
    channel_menu,
    load_balancing_menu,
    logs_menu,
    oauth_menu,
    sort_primitives,
    stats_menu,
    status_update_banner,
)


def _legacy_split_number_rows(n: int, max_cols: int = 6) -> list[list[int]]:
    if n <= 0:
        return []
    rows_count = math.ceil(n / max_cols)
    base = n // rows_count
    extra = n % rows_count
    rows: list[list[int]] = []
    current = 1
    for row_index in range(rows_count):
        size = base + (1 if row_index < extra else 0)
        rows.append(list(range(current, current + size)))
        current += size
    return rows


def _legacy_move_top(draft: list[str], selected: set[int]) -> list[str]:
    indexes = [index - 1 for index in sorted(selected)]
    chosen = [draft[index] for index in indexes]
    rest = [value for index, value in enumerate(draft) if index not in indexes]
    return chosen + rest


def _legacy_move_bottom(draft: list[str], selected: set[int]) -> list[str]:
    indexes = [index - 1 for index in sorted(selected)]
    chosen = [draft[index] for index in indexes]
    rest = [value for index, value in enumerate(draft) if index not in indexes]
    return rest + chosen


def _legacy_move_up(
    draft: list[str], selected: set[int],
) -> tuple[list[str], set[int]]:
    result = list(draft)
    zero_based = {index - 1 for index in selected}
    for index in range(1, len(result)):
        if index in zero_based and index - 1 not in zero_based:
            result[index - 1], result[index] = result[index], result[index - 1]
            zero_based.remove(index)
            zero_based.add(index - 1)
    return result, {index + 1 for index in zero_based}


def _legacy_move_down(
    draft: list[str], selected: set[int],
) -> tuple[list[str], set[int]]:
    result = list(draft)
    zero_based = {index - 1 for index in selected}
    for index in range(len(result) - 2, -1, -1):
        if index in zero_based and index + 1 not in zero_based:
            result[index + 1], result[index] = result[index], result[index + 1]
            zero_based.remove(index)
            zero_based.add(index + 1)
    return result, {index + 1 for index in zero_based}


def _outcome(function, *args):
    try:
        return "return", function(*args)
    except Exception as exc:
        return "raise", type(exc), exc.args


@pytest.mark.parametrize(
    ("n", "max_cols"),
    [
        (-1, 6),
        (0, 6),
        (1, 6),
        (6, 6),
        (7, 6),
        (11, 6),
        (12, 6),
        (13, 6),
        (14, 6),
        (3, 1),
        (7, 4),
        (0, 0),
        (1, 0),
        (1, -1),
    ],
)
def test_split_number_rows_matches_all_legacy_boundaries(n, max_cols):
    assert _outcome(sort_primitives.split_number_rows, n, max_cols) == _outcome(
        _legacy_split_number_rows, n, max_cols,
    )


_MOVE_FUNCTIONS = [
    (sort_primitives.move_top, _legacy_move_top),
    (sort_primitives.move_bottom, _legacy_move_bottom),
    (sort_primitives.move_up, _legacy_move_up),
    (sort_primitives.move_down, _legacy_move_down),
]
_MOVE_CASES = [
    ([], set()),
    (["a"], set()),
    (["a"], {1}),
    (["a", "b", "c", "d"], {1}),
    (["a", "b", "c", "d"], {4}),
    (["a", "b", "c", "d"], {1, 2}),
    (["a", "b", "c", "d"], {2, 3}),
    (["a", "b", "c", "d"], {1, 3}),
    (["a", "b", "c", "d"], {2, 4}),
    (["a", "b", "c", "d"], {1, 2, 3, 4}),
    (["a", "b", "c", "d"], {0}),
    (["a", "b", "c", "d"], {5}),
    (["a", "b", "c", "d"], {-5}),
]


@pytest.mark.parametrize(("actual", "legacy"), _MOVE_FUNCTIONS)
@pytest.mark.parametrize(("draft", "selected"), _MOVE_CASES)
def test_move_primitive_matches_legacy_without_mutating_inputs(
    actual, legacy, draft, selected,
):
    actual_draft, actual_selected = list(draft), set(selected)
    legacy_draft, legacy_selected = list(draft), set(selected)

    assert _outcome(actual, actual_draft, actual_selected) == _outcome(
        legacy, legacy_draft, legacy_selected,
    )
    assert actual_draft == draft
    assert actual_selected == selected


def test_all_four_menu_adapters_share_the_same_five_primitives():
    expected = {
        "_split_number_rows": sort_primitives.split_number_rows,
        "_move_top": sort_primitives.move_top,
        "_move_bottom": sort_primitives.move_bottom,
        "_move_up": sort_primitives.move_up,
        "_move_down": sort_primitives.move_down,
    }
    for menu in (apikey_menu, channel_menu, oauth_menu, load_balancing_menu):
        assert {name: getattr(menu, name) for name in expected} == expected


@pytest.mark.parametrize(
    ("status_value", "update_value", "expected_suffix"),
    [
        (None, None, ""),
        ("", "", ""),
        ("⚠ <b>status</b>", "", "\n\n⚠ <b>status</b>"),
        (None, "🆕 <code>v1</code>", "\n\n🆕 <code>v1</code>"),
        (
            "⚠ <b>status</b>",
            "🆕 <code>v1</code>",
            "\n\n⚠ <b>status</b>\n🆕 <code>v1</code>",
        ),
        (RuntimeError("status"), "update", "\n\nupdate"),
        ("status", RuntimeError("update"), "\n\nstatus"),
        (RuntimeError("status"), RuntimeError("update"), ""),
    ],
)
def test_status_update_banner_preserves_order_errors_and_html_bytes(
    monkeypatch, status_value, update_value, expected_suffix,
):
    calls = []

    def value(name, result):
        calls.append(name)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(
        status_monitor,
        "get_active_summary",
        lambda: value("status", status_value),
    )
    monkeypatch.setattr(
        update_checker,
        "get_update_banner",
        lambda: value("update", update_value),
    )
    text = "正文\n<code>x&amp;y</code>"
    expected = text + expected_suffix

    actual = status_update_banner.suffix_status_update_banner(text)

    assert calls == ["status", "update"]
    assert actual.encode("utf-8") == expected.encode("utf-8")


def test_logs_and_stats_share_the_exact_banner_function():
    expected = status_update_banner.suffix_status_update_banner
    assert logs_menu._maybe_suffix_status_banner is expected
    assert stats_menu._maybe_suffix_status_banner is expected


def test_oauth_bridge_exports_direct_stable_modules_and_runtime_facades(monkeypatch):
    assert menu_bridge.model_metadata is model_metadata
    assert menu_bridge.notifier is notifier
    assert menu_bridge.oauth_errors is oauth_errors
    assert menu_bridge.status_monitor is status_monitor
    assert menu_bridge.update_checker is update_checker
    assert menu_bridge.antigravity_provider is antigravity

    marker = object()
    monkeypatch.setattr(oauth_ids, "account_key", lambda account: marker)
    assert menu_bridge.account_key({}) is marker

    assert not hasattr(menu_bridge, "_ModuleProxy")
    for removed in (
        "affinity",
        "config",
        "cooldown",
        "cursor_model_catalog",
        "cursor_provider",
        "load_balancing",
        "log_db",
        "oauth_manager",
        "openai_provider",
        "state_db",
        "xai_provider",
    ):
        assert not hasattr(menu_bridge, removed)

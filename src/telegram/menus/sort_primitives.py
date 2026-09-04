"""Pure 1-based ordering primitives shared by Telegram menu adapters."""

from __future__ import annotations

import math


def split_number_rows(n: int, max_cols: int = 6) -> list[list[int]]:
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


def move_top(draft: list[str], selected: set[int]) -> list[str]:
    indexes = [index - 1 for index in sorted(selected)]
    chosen = [draft[index] for index in indexes]
    rest = [value for index, value in enumerate(draft) if index not in indexes]
    return chosen + rest


def move_bottom(draft: list[str], selected: set[int]) -> list[str]:
    indexes = [index - 1 for index in sorted(selected)]
    chosen = [draft[index] for index in indexes]
    rest = [value for index, value in enumerate(draft) if index not in indexes]
    return rest + chosen


def move_up(draft: list[str], selected: set[int]) -> tuple[list[str], set[int]]:
    result = list(draft)
    zero_based = {index - 1 for index in selected}
    for index in range(1, len(result)):
        if index in zero_based and index - 1 not in zero_based:
            result[index - 1], result[index] = result[index], result[index - 1]
            zero_based.remove(index)
            zero_based.add(index - 1)
    return result, {index + 1 for index in zero_based}


def move_down(draft: list[str], selected: set[int]) -> tuple[list[str], set[int]]:
    result = list(draft)
    zero_based = {index - 1 for index in selected}
    for index in range(len(result) - 2, -1, -1):
        if index in zero_based and index + 1 not in zero_based:
            result[index + 1], result[index] = result[index], result[index + 1]
            zero_based.remove(index)
            zero_based.add(index + 1)
    return result, {index + 1 for index in zero_based}

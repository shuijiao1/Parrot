"""Telegram rendering adapter for the shared structured-log parser."""

from __future__ import annotations

import re
from typing import Any

from src.management_control.observability.inspector import (
    filter_items,
    fmt_size,
    parse_request_body,
    parse_response_body,
    selected_item,
    sort_items,
)

Item = dict[str, Any]
SORT_KEYS = ("original", "reverse", "size", "type")
SORT_LABELS = {"original": "原始", "reverse": "倒序", "size": "大小", "type": "类型"}
KIND_LABELS = {
    "assistant": "助手消息", "user": "用户消息", "system": "系统消息",
    "developer": "开发者消息", "tool": "工具消息", "instructions": "指令消息",
    "params": "请求参数", "metadata": "元数据", "tools": "工具定义",
    "tool_choice": "工具选择", "tool_call": "工具调用", "tool_result": "工具结果",
    "reasoning": "思考内容", "usage": "用量统计", "error": "错误信息",
    "finish": "结束原因", "refusal": "拒绝内容", "message": "消息",
    "input": "输入内容", "output": "输出内容", "response": "响应元信息",
    "request": "请求内容", "event": "原始事件", "raw_request": "原始请求",
    "raw_response": "原始响应",
}
SUMMARY_LABELS = {
    "function_call_output": "函数调用结果", "custom_tool_call_output": "自定义工具结果",
    "mcp_tool_call_output": "MCP 工具结果", "function_call": "函数调用",
    "custom_tool_call": "自定义工具调用", "mcp_tool_call": "MCP 工具调用",
    "tool_call": "工具调用", "tool_result": "工具结果", "output_text": "输出文本",
    "input_text": "输入文本", "reasoning_summary_text": "思考摘要",
    "reasoning": "思考内容", "assistant": "助手消息", "user": "用户消息",
    "system": "系统消息", "developer": "开发者消息", "usage": "用量统计",
    "metadata": "元数据", "params": "请求参数", "tools": "工具定义", "text": "文本",
}
KIND_SHORT_LABELS = {
    "assistant": "助手", "user": "用户", "system": "系统", "developer": "开发",
    "instructions": "指令", "params": "参数", "metadata": "元数据", "tools": "工具定义",
    "tool_choice": "工具选择", "tool_call": "调用", "tool_result": "结果",
    "reasoning": "思考", "usage": "用量", "error": "错误", "finish": "结束",
    "refusal": "拒绝", "message": "消息", "response": "响应", "event": "事件",
}
SUMMARY_SHORT_LABELS = {
    "函数调用结果": "函数结果", "自定义工具结果": "自定义结果", "MCP 工具结果": "MCP结果",
    "函数调用": "函数", "自定义工具调用": "自定义", "MCP 工具调用": "MCP",
    "工具调用": "调用", "工具结果": "结果", "输出文本": "输出", "输入文本": "输入",
    "思考摘要": "思考摘要", "思考内容": "思考", "助手消息": "助手",
    "用户消息": "用户", "系统消息": "系统", "开发者消息": "开发",
    "用量统计": "用量", "请求参数": "参数", "工具定义": "工具定义",
}


def _compact_ws(text: str, limit: int = 42) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return value if len(value) <= limit else value[:limit - 1] + "…"


def kind_label(kind: str | None) -> str:
    key = str(kind or "")
    return KIND_LABELS.get(key, key or "消息")


def summary_label(summary: str | None) -> str:
    value = str(summary or "")
    for raw, label in sorted(SUMMARY_LABELS.items(), key=lambda item: len(item[0]), reverse=True):
        value = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(raw)}(?![A-Za-z0-9_])", label, value)
    return value


def kind_short_label(kind: str | None) -> str:
    key = str(kind or "")
    return KIND_SHORT_LABELS.get(key, kind_label(key))


def summary_short_label(summary: str | None) -> str:
    value = summary_label(summary)
    for raw, label in sorted(SUMMARY_SHORT_LABELS.items(), key=lambda item: len(item[0]), reverse=True):
        value = value.replace(raw, label)
    parts = [part.strip() for part in value.split("·") if part.strip()]
    if len(parts) >= 2 and parts[0] in {"助手", "用户", "系统", "开发", "思考"}:
        parts = parts[1:]
    return " · ".join(parts)


def next_sort(sort_key: str | None) -> str:
    current = sort_key if sort_key in SORT_KEYS else "original"
    return SORT_KEYS[(SORT_KEYS.index(current) + 1) % len(SORT_KEYS)]


def button_label(item: Item, *, selected: bool = False, compact: bool = True) -> str:
    prefix = "✅ " if selected else ""
    seq = int(item.get("seq") or 0)
    kind = str(item.get("kind") or "message")
    summary = summary_short_label(str(item.get("summary") or "")) if compact else summary_label(str(item.get("summary") or ""))
    size = fmt_size(int(item.get("size") or 0))
    kind_text = kind_short_label(kind) if compact else kind_label(kind)
    if compact:
        if kind == "tool_call":
            parts = [part.strip() for part in summary.split("·") if part.strip()]
            if len(parts) >= 2 and parts[0] in {"函数", "调用", "自定义", "MCP"}:
                summary = " · ".join(parts[1:])
        elif kind == "tool_result" and summary in {"函数结果", "自定义结果", "MCP结果", "结果"}:
            summary = ""
        base = f"{prefix}#{seq} {kind_text}" + (f" · {summary}" if summary else "") + f" · {size}"
        return _compact_ws(base, 34)
    return _compact_ws(f"{prefix}#{seq} {kind_text} · {summary} · {size}", 58)


__all__ = [
    "SORT_LABELS", "button_label", "filter_items", "fmt_size", "kind_label",
    "kind_short_label", "next_sort", "parse_request_body", "parse_response_body",
    "selected_item", "sort_items", "summary_label",
]

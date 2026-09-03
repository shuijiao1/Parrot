"""Request log list, detail and protected body inspection controls."""

from __future__ import annotations

import copy
import heapq
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from src import config as config_module
from src import log_db as log_db_module
from src import oauth_manager as oauth_manager_module
from src.management_auth import Capability
from src.management_control.context import ManagementContext
from src.management_control.errors import ManagementError, ManagementErrorCode

from . import inspector
from .common import PageResult, camelize, page_slice, require, revision_for, sanitize_credentials, utc_datetime


class LogBodyKind(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"


class RequestLogStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    CANCELLED = "cancelled"
    PENDING = "pending"


class RequestProtocol(str, Enum):
    ANTHROPIC = "anthropic"
    CHAT = "chat"
    RESPONSES = "responses"
    RESPONSES_WS = "responses_ws"


class RequestLogSort(str, Enum):
    CREATED_AT = "createdAt"
    STATUS = "status"
    LATENCY = "latency"
    COST = "cost"
    MODEL = "model"


@dataclass(frozen=True, slots=True)
class RequestLogQuery:
    statuses: tuple[RequestLogStatus, ...] = ()
    api_keys: tuple[str, ...] = ()
    models: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()
    protocols: tuple[RequestProtocol, ...] = ()
    query: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    sort: RequestLogSort = RequestLogSort.CREATED_AT
    descending: bool = True
    page: int = 1
    page_size: int = 50


class BodySort(str, Enum):
    ORIGINAL = "original"
    REVERSE = "reverse"
    SIZE = "size"
    TYPE = "type"


@dataclass(frozen=True, slots=True)
class LogBodyPageResult:
    items: tuple[dict[str, Any], ...]
    page: int
    page_size: int
    total: int
    kind_counts: tuple[dict[str, Any], ...]

    @property
    def has_next(self) -> bool:
        return self.page * self.page_size < self.total


_SCAN_CHUNK = 200


class LogsControl:
    def __init__(self, *, log_db=log_db_module, config=config_module, oauth_manager=oauth_manager_module) -> None:
        self.log_db = log_db
        self.config = config
        self.oauth_manager = oauth_manager

    @staticmethod
    def _status_pushdown(statuses: tuple[RequestLogStatus, ...]) -> str | None:
        return statuses[0].value if len(statuses) == 1 else None

    def _base_filters(self, query: RequestLogQuery) -> dict[str, Any]:
        return {
            "status": self._status_pushdown(query.statuses),
            "api_keys": list(query.api_keys) or None,
            "models": list(query.models) or None,
            "channel_keys": list(query.channels) or None,
        }

    @staticmethod
    def _matches(row: dict[str, Any], query: RequestLogQuery) -> bool:
        if len(query.statuses) > 1 and str(row.get("status") or "") not in {item.value for item in query.statuses}:
            return False
        protocol = str(row.get("protocol") or row.get("ingress_protocol") or "")
        if query.protocols and protocol not in {item.value for item in query.protocols}:
            return False
        created = utc_datetime(row.get("created_at"))
        if query.started_at is not None and (created is None or created < query.started_at):
            return False
        if query.ended_at is not None and (created is None or created > query.ended_at):
            return False
        if query.query:
            needle = query.query.casefold()
            values = (
                row.get("request_id"), row.get("requested_model"), row.get("final_model"),
                row.get("final_channel_key"), row.get("api_key_name"), row.get("error_message"),
            )
            if not any(needle in str(value or "").casefold() for value in values):
                return False
        return True

    @staticmethod
    def _sort_value(row: dict[str, Any], sort: RequestLogSort) -> Any:
        if sort is RequestLogSort.STATUS:
            return str(row.get("status") or "")
        if sort is RequestLogSort.LATENCY:
            return float(row.get("duration_ms") or row.get("total_time_ms") or 0)
        if sort is RequestLogSort.COST:
            return int(row.get("cost_ticks") or row.get("cost_usd_ticks") or 0)
        if sort is RequestLogSort.MODEL:
            return str(row.get("requested_model") or row.get("final_model") or "").casefold()
        dt = utc_datetime(row.get("created_at"))
        return dt.timestamp() if dt is not None else 0.0

    def list_logs(self, context: ManagementContext, query: RequestLogQuery) -> PageResult[dict[str, Any]]:
        require(context)
        filters = self._base_filters(query)
        requires_memory = bool(
            len(query.statuses) > 1 or query.protocols or query.query
            or query.started_at is not None or query.ended_at is not None
            or query.sort is not RequestLogSort.CREATED_AT or not query.descending
        )
        if not requires_memory:
            total = int(self.log_db.recent_logs_count(**filters))
            rows = self.log_db.recent_logs(
                query.page_size,
                offset=(query.page - 1) * query.page_size,
                **filters,
            )
            return PageResult(
                tuple(self._list_record(row) for row in rows),
                query.page, query.page_size, total,
            )
        total_candidates = int(self.log_db.recent_logs_count(**filters))
        matched = 0

        def candidates():
            nonlocal matched
            for offset in range(0, total_candidates, _SCAN_CHUNK):
                chunk = self.log_db.recent_logs(
                    min(_SCAN_CHUNK, total_candidates - offset), offset=offset, **filters,
                )
                if not chunk:
                    break
                for row in chunk:
                    if self._matches(row, query):
                        matched += 1
                        yield row

        top_k = query.page * query.page_size
        selector = heapq.nlargest if query.descending else heapq.nsmallest
        selected = selector(
            top_k, candidates(), key=lambda row: self._sort_value(row, query.sort),
        )
        start = (query.page - 1) * query.page_size
        rows = selected[start:start + query.page_size]
        return PageResult(
            tuple(self._list_record(row) for row in rows),
            query.page, query.page_size, matched,
        )

    def list_telegram(
        self,
        context: ManagementContext,
        *,
        limit: int,
        offset: int,
        api_keys: list[str] | None = None,
        models: list[str] | None = None,
        channel_keys: list[str] | None = None,
    ) -> tuple[list[dict], int]:
        """Exact current-store query used by the frozen TG paging adapter."""
        require(context)
        filters = {"api_keys": api_keys, "models": models, "channel_keys": channel_keys}
        total = int(self.log_db.recent_logs_count(**filters))
        rows = self.log_db.recent_logs(limit, offset=offset, **filters)
        return copy.deepcopy(rows), total

    def telegram_count(self, context: ManagementContext, **filters) -> int:
        require(context)
        return int(self.log_db.recent_logs_count(**filters))

    def telegram_recent(self, context: ManagementContext, *, limit: int, offset: int, **filters) -> list[dict]:
        require(context)
        return copy.deepcopy(self.log_db.recent_logs(limit, offset=offset, **filters))

    def recent_values(self, context: ManagementContext, kind: str) -> list[str]:
        require(context)
        return copy.deepcopy(self.log_db.recent_log_values(kind))

    def cost_for_log(self, context: ManagementContext, row: dict | None) -> dict:
        require(context)
        return copy.deepcopy(self.log_db.cost_for_log(row))

    def _list_record(self, row: dict[str, Any]) -> dict[str, Any]:
        clean = sanitize_credentials(dict(row))
        return {
            "id": str(clean.get("request_id") or clean.get("id") or ""),
            "status": str(clean.get("status") or "unknown"),
            "createdAt": utc_datetime(clean.get("created_at")),
            "apiKeyName": clean.get("api_key_name"),
            "requestedModel": clean.get("requested_model"),
            "finalModel": clean.get("final_model"),
            "channelId": clean.get("final_channel_key"),
            "protocol": clean.get("protocol") or clean.get("ingress_protocol"),
            "transport": clean.get("transport"),
            "retryCount": int(clean.get("retry_count") or clean.get("total_retries") or 0),
            "durationMilliseconds": clean.get("duration_ms") or clean.get("total_time_ms"),
            "inputTokens": int(clean.get("input_tokens") or clean.get("prompt_tokens") or 0),
            "outputTokens": int(clean.get("output_tokens") or clean.get("completion_tokens") or 0),
            "costTicks": int(clean.get("cost_ticks") or clean.get("cost_usd_ticks") or 0),
            "error": clean.get("error_message"),
            "revision": revision_for(clean),
        }

    def filter_options(self, context: ManagementContext) -> dict[str, Any]:
        require(context)
        total = int(self.log_db.recent_logs_count())
        fields = {
            "apiKeys": "api_key_name", "models": "requested_model",
            "channels": "final_channel_key", "statuses": "status",
            "protocols": "protocol",
        }
        counts_by_field: dict[str, dict[str, int]] = {
            public: {} for public in fields
        }
        for offset in range(0, total, _SCAN_CHUNK):
            rows = self.log_db.recent_logs(min(_SCAN_CHUNK, total - offset), offset=offset)
            if not rows:
                break
            for row in rows:
                for public, storage in fields.items():
                    value = row.get(storage)
                    if public == "protocols" and not value:
                        value = row.get("ingress_protocol")
                    if value:
                        key = str(value)
                        counts = counts_by_field[public]
                        counts[key] = counts.get(key, 0) + 1
        result: dict[str, list[dict[str, Any]]] = {}
        for public, counts in counts_by_field.items():
            result[public] = [
                {"value": value, "count": count}
                for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            ]
        result["revision"] = revision_for(result)
        return result

    def detail(self, context: ManagementContext, log_id: str) -> dict[str, Any]:
        require(context)
        raw = self.log_db.log_detail(log_id)
        if not raw or not raw.get("log"):
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        detail = raw.get("detail") or {}
        log = sanitize_credentials(raw.get("log") or {})
        result = {
            "id": log_id,
            "log": self._list_record(log),
            "stages": camelize(sanitize_credentials(raw.get("proxy_chain") or [])),
            "attempts": camelize(sanitize_credentials(raw.get("retry_chain") or [])),
            "localWebRounds": camelize(sanitize_credentials(raw.get("local_web_log") or [])),
            "billingAttempts": camelize(sanitize_credentials(raw.get("billing_attempts") or [])),
            "requestBodyAvailable": bool(detail.get("request_body")),
            "responseBodyAvailable": bool(detail.get("response_body")),
            "requestHeadersAvailable": bool(detail.get("request_headers")),
        }
        result["revision"] = revision_for(result)
        return result

    def raw_detail_for_telegram(self, context: ManagementContext, log_id: str) -> dict:
        require(context)
        return copy.deepcopy(self.log_db.log_detail(log_id))

    def _raw_body(self, context: ManagementContext, log_id: str, kind: LogBodyKind) -> Any:
        require(context, Capability.LOG_BODY_READ)
        raw = self.log_db.log_detail(log_id)
        if not raw or not raw.get("log"):
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        detail = raw.get("detail") or {}
        value = detail.get("request_body" if kind is LogBodyKind.REQUEST else "response_body")
        if value is None or value == "":
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        return value

    @staticmethod
    def _sanitize_raw(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return sanitize_credentials(value)
        text = str(value)
        try:
            parsed = json.loads(text)
        except Exception:
            return re.sub(
                r"(?i)(authorization|proxy-authorization|x-api-key|api-key)\s*:\s*([^\s,;]+)",
                lambda match: f"{match.group(1)}: <redacted>",
                text,
            )
        return sanitize_credentials(parsed)

    def body_items(
        self,
        context: ManagementContext,
        log_id: str,
        *,
        kind: LogBodyKind,
        query: str | None,
        sort: BodySort,
        item_kind: str | None,
        page: int,
        page_size: int,
    ) -> LogBodyPageResult:
        raw = self._raw_body(context, log_id, kind)
        clean = self._sanitize_raw(raw)
        parsed = inspector.parse_request_body(clean) if kind is LogBodyKind.REQUEST else inspector.parse_response_body(clean)
        searched = inspector.filter_items(parsed, query)
        counts: dict[str, int] = {}
        for item in searched:
            item_type = str(item.get("kind") or "")
            counts[item_type] = counts.get(item_type, 0) + 1
        items = searched
        if item_kind:
            items = [item for item in items if str(item.get("kind") or "") == item_kind]
        items = inspector.sort_items(items, sort.value)
        result = page_slice(items, page=page, page_size=page_size)
        return LogBodyPageResult(
            tuple(camelize(sanitize_credentials(item)) for item in result.items),
            page,
            page_size,
            result.total,
            tuple({"kind": key, "count": counts[key]} for key in sorted(counts)),
        )

    def body_item(
        self,
        context: ManagementContext,
        log_id: str,
        *,
        kind: LogBodyKind,
        item_id: str,
    ) -> dict[str, Any]:
        raw = self._raw_body(context, log_id, kind)
        clean = self._sanitize_raw(raw)
        items = inspector.parse_request_body(clean) if kind is LogBodyKind.REQUEST else inspector.parse_response_body(clean)
        try:
            seq = int(item_id.removeprefix("item_"))
        except (TypeError, ValueError):
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        for item in items:
            if int(item.get("seq") or 0) == seq:
                result = camelize(sanitize_credentials(item))
                result["id"] = f"item_{seq}"
                return result
        raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)

    def raw_body(self, context: ManagementContext, log_id: str, *, kind: LogBodyKind) -> dict[str, Any]:
        raw = self._raw_body(context, log_id, kind)
        return {"logId": log_id, "kind": kind.value, "body": self._sanitize_raw(raw)}

    def log_store_bodies(self, context: ManagementContext) -> bool:
        require(context)
        return self.config.get().get("logStoreBodies", True) is not False

    def configured_api_keys(self, context: ManagementContext) -> list[str]:
        require(context)
        keys = self.config.get().get("apiKeys") or {}
        return [str(key) for key in keys] if isinstance(keys, dict) else []

    def configured_channels(self, context: ManagementContext) -> list[str]:
        require(context)
        values: list[str] = []
        for channel in self.config.get().get("channels") or []:
            if isinstance(channel, dict) and channel.get("name"):
                values.append("api:" + str(channel["name"]))
        for account in self.oauth_manager.list_accounts():
            key = str(self.oauth_manager._account_key(account) or "")
            if key:
                values.append("oauth:" + key)
        return values


DEFAULT_LOGS_CONTROL = LogsControl()

"""Actor-bound network plans, atomic commits, cache and monitor use cases."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.management_auth import Capability
from src.management_control.context import AuditSink, ManagementContext
from src.management_control.errors import ErrorField, ManagementError, ManagementErrorCode
from src.management_control.models.common import DomainControl, stable_revision
from src.management_control.observability.common import sanitize_credentials
from src.management_control.operations import ManagementOperation, OperationStore

from .gateway import DEFAULT_NETWORK_GATEWAY, NetworkGateway
from .models import (
    DnsCacheEntry,
    DnsCachePage,
    DnsSettings,
    MonitorChannelSettings,
    MonitorCoreSettings,
    NetworkCheck,
    NetworkCheckPage,
    NetworkMonitorSettings,
    NetworkSettings,
    NetworkTestPlan,
    ProxySummary,
    Socks5Settings,
)


class PlanState(str, Enum):
    PREPARED = "prepared"
    COMMITTED = "committed"


@dataclass(frozen=True, slots=True)
class _Plan:
    id: str
    kind: str
    actor: str
    session: str | None
    revision: str
    authority_fingerprint: str
    value: Any
    test: dict[str, Any]
    passed: bool
    created_at: float
    expires_at: float
    state: PlanState = PlanState.PREPARED


def _safe_url(value: str, *, mask_user: bool = False, drop_path: bool = False) -> str:
    raw = str(value or "")
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return str(sanitize_credentials(raw))
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        if mask_user and (parsed.username is not None or parsed.password is not None):
            netloc = "***:***@" + netloc
        query = []
        if not drop_path:
            for key, item in parse_qsl(parsed.query, keep_blank_values=True):
                cleaned = sanitize_credentials({key: item}).get(key)
                query.append((key, "[REDACTED]" if cleaned != item else item))
        result = urlunsplit((parsed.scheme, netloc, "" if drop_path else parsed.path, urlencode(query), ""))
        # Any original userinfo is already replaced byte-for-byte above. Keep
        # the explicit mask for clients instead of letting the generic sanitizer
        # remove the whole safe placeholder.
        return result if mask_user else str(sanitize_credentials(result))
    except Exception:
        return str(sanitize_credentials(raw))


def _safe_dns_server(value: Any) -> str:
    raw = str(value or "")
    return _safe_url(raw) if "://" in raw else str(sanitize_credentials(raw))


def _utc(seconds: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(seconds), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _rfc3339(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class NetworkControl(DomainControl):
    def __init__(
        self,
        *,
        gateway: NetworkGateway = DEFAULT_NETWORK_GATEWAY,
        operations: OperationStore | None = None,
        audit_sink: AuditSink | None = None,
        now: Callable[[], float] = time.time,
        ttl_seconds: int = 300,
        max_plans: int = 256,
        start_worker: Callable[[Callable[[], None]], None] | None = None,
    ) -> None:
        super().__init__(audit_sink=audit_sink)
        self.gateway = gateway
        self.operations = operations
        self._now = now
        self.ttl_seconds = ttl_seconds
        self.max_plans = max_plans
        self._plans: OrderedDict[str, _Plan] = OrderedDict()
        self._expired: OrderedDict[str, tuple[str, str | None]] = OrderedDict()
        self._lock = threading.RLock()
        self._start_worker = start_worker or self._thread_worker

    @staticmethod
    def _thread_worker(worker: Callable[[], None]) -> None:
        threading.Thread(target=worker, daemon=True, name="network-operation").start()

    def _channels(self) -> list[Any]:
        try:
            return list(self.gateway.channels())
        except Exception as exc:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc

    def _api_channel_ids(self) -> tuple[str, ...]:
        cfg = self.gateway.config_get()
        values = []
        for entry in cfg.get("channels") or []:
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get("name") or "").strip()
            if name:
                values.append("api:" + name)
        return tuple(values)

    def _network(self, cfg: Mapping[str, Any] | None = None) -> NetworkSettings:
        cfg = self.gateway.config_get() if cfg is None else cfg
        net = cfg.get("network") if isinstance(cfg.get("network"), Mapping) else {}
        dns = net.get("dns") if isinstance(net.get("dns"), Mapping) else {}
        socks = net.get("socks5") if isinstance(net.get("socks5"), Mapping) else {}
        proxies = net.get("proxies") if isinstance(net.get("proxies"), Mapping) else {}
        groups = net.get("groups") if isinstance(net.get("groups"), Mapping) else {}
        routing = net.get("routing") if isinstance(net.get("routing"), Mapping) else {}
        raw_servers = dns.get("servers") or ["8.8.8.8"]
        servers = tuple(_safe_dns_server(item) for item in raw_servers)
        raw_url = str(socks.get("url") or "").strip()
        masked = _safe_url(raw_url, mask_user=True, drop_path=True) if raw_url else None
        rule_count = sum(1 for key in routing if key != "default")
        rule_count += sum(len(value) for value in routing.values() if isinstance(value, Mapping))
        values = {
            "dns": DnsSettings(
                servers=servers,
                cacheTtlSeconds=max(0, self._safe_int(dns.get("cacheTtlSeconds"), 300)),
            ),
            "socks5": Socks5Settings(
                enabled=bool(socks.get("enabled")) and bool(raw_url),
                configured=bool(raw_url),
                maskedUrl=masked,
            ),
            "proxySummary": ProxySummary(
                proxyCount=len(proxies), groupCount=len(groups), ruleCount=rule_count,
                defaultRoute=str(routing.get("default") or "direct"),
                directFallback=bool(routing.get("directFallback", False)),
            ),
        }
        public = {key: asdict(value) for key, value in values.items()}
        return NetworkSettings(**values, revision=stable_revision(public))

    @staticmethod
    def _safe_int(value: Any, default: int) -> int:
        try:
            if isinstance(value, bool):
                raise ValueError
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default

    def get_settings(self, context: ManagementContext | None) -> NetworkSettings:
        self._read(context)
        try:
            return self._network()
        except ManagementError:
            raise
        except Exception as exc:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc

    @staticmethod
    def _fingerprint(value: Any) -> str:
        payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def _network_authority_fingerprint(cls, cfg: Mapping[str, Any]) -> str:
        # This private digest detects concurrent credential-only changes without
        # putting secret material into the public revision or any response.
        return cls._fingerprint(copy.deepcopy(cfg.get("network") or {}))

    def _purge(self) -> None:
        now = self._now()
        for plan_id, plan in tuple(self._plans.items()):
            if plan.expires_at <= now:
                self._plans.pop(plan_id, None)
                self._expired[plan_id] = (plan.actor, plan.session)
        while len(self._expired) > self.max_plans:
            self._expired.popitem(last=False)
        while len(self._plans) >= self.max_plans:
            self._plans.popitem(last=False)

    @staticmethod
    def _visible(context: ManagementContext, plan: _Plan) -> bool:
        return plan.session == context.actor.session_id if plan.session is not None else plan.actor == context.actor.subject_id

    def _lookup(self, context: ManagementContext, plan_id: str, kind: str) -> _Plan:
        self._purge()
        plan = self._plans.get(plan_id)
        if plan is None:
            if self._expired.get(plan_id) == (context.actor.subject_id, context.actor.session_id):
                raise ManagementError(ManagementErrorCode.STATE_CONFLICT, "Network test plan has expired")
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        if not self._visible(context, plan) or plan.kind != kind:
            raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
        if plan.state is not PlanState.PREPARED:
            raise ManagementError(ManagementErrorCode.STATE_CONFLICT)
        return plan

    def _public_test(self, kind: str, test: Mapping[str, Any]) -> dict[str, Any]:
        clean = sanitize_credentials(copy.deepcopy(dict(test)))
        if kind == "socks5":
            clean.pop("url", None)
            clean.pop("display_url", None)
            clean.pop("displayUrl", None)
        return clean

    def _public_plan(self, plan: _Plan) -> NetworkTestPlan:
        tested = (
            {"servers": tuple(_safe_dns_server(item) for item in plan.value)}
            if plan.kind == "dns"
            else {"configured": True, "maskedUrl": _safe_url(str(plan.value), mask_user=True, drop_path=True)}
        )
        return NetworkTestPlan(
            id=plan.id,
            kind=plan.kind,
            passed=plan.passed,
            tested=tested,
            result=self._public_test(plan.kind, plan.test),
            createdAt=datetime.fromtimestamp(plan.created_at, tz=timezone.utc),
            expiresAt=datetime.fromtimestamp(plan.expires_at, tz=timezone.utc),
            revision=plan.revision,
        )

    def _publish_plan(self, context: ManagementContext, *, kind: str, revision: str, authority_fingerprint: str, value: Any, test: dict[str, Any]) -> _Plan:
        now = self._now()
        plan = _Plan(
            id="nplan_" + secrets.token_urlsafe(18), kind=kind,
            actor=context.actor.subject_id, session=context.actor.session_id,
            revision=revision, authority_fingerprint=authority_fingerprint,
            value=copy.deepcopy(value), test=copy.deepcopy(test),
            passed=bool(test.get("ok")), created_at=now, expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._purge()
            self._plans[plan.id] = plan
        self._audit(context, f"network.{kind}.test", plan.id, "succeeded")
        return plan

    def _operations(self, operations: OperationStore | None) -> OperationStore:
        store = operations or self.operations
        if store is None:
            raise ManagementError(ManagementErrorCode.SERVICE_NOT_READY, retryable=True)
        return store

    def start_dns_test(
        self, context: ManagementContext | None, servers: list[str], *, operations: OperationStore | None = None,
    ) -> ManagementOperation:
        actual = self._write(context, Capability.WRITE)
        try:
            normalized = self.gateway.normalize_dns(list(servers))
        except Exception as exc:
            self._audit(actual, "network.dns.test", "dns", "failed")
            raise self._validation("servers", "invalid_dns", "DNS server list is invalid") from exc
        with self.gateway.serialized_updates():
            cfg = self.gateway.config_get()
            revision = self._network(cfg).revision
            authority_fingerprint = self._network_authority_fingerprint(cfg)
        store = self._operations(operations)
        operation = store.create(actual, kind="network.dns.test", cancellable=False)

        def worker() -> None:
            try:
                store.mark_running(operation.id)
                test = self.gateway.test_dns(list(normalized))
                plan = self._publish_plan(actual, kind="dns", revision=revision, authority_fingerprint=authority_fingerprint, value=normalized, test=test)
                store.succeed(operation.id, {"plan": self._plan_result(plan)})
            except Exception:
                try:
                    store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
                except ManagementError:
                    pass
                self._audit(actual, "network.dns.test", "dns", "failed")
        try:
            self._start_worker(worker)
        except Exception as exc:
            store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True, operation_id=operation.id) from exc
        return operation

    def start_socks5_test(
        self, context: ManagementContext | None, url: str, *, operations: OperationStore | None = None,
    ) -> ManagementOperation:
        actual = self._write(context, Capability.SECRETS_WRITE)
        try:
            normalized = self.gateway.normalize_socks5(url).url
        except Exception as exc:
            self._audit(actual, "network.socks5.test", "socks5", "failed")
            raise self._validation("url", "invalid_socks5", "SOCKS5 URL is invalid") from exc
        with self.gateway.serialized_updates():
            cfg = self.gateway.config_get()
            revision = self._network(cfg).revision
            authority_fingerprint = self._network_authority_fingerprint(cfg)
        store = self._operations(operations)
        operation = store.create(actual, kind="network.socks5.test", cancellable=False)

        def worker() -> None:
            try:
                store.mark_running(operation.id)
                test = asyncio.run(self.gateway.test_socks5(normalized))
                plan = self._publish_plan(actual, kind="socks5", revision=revision, authority_fingerprint=authority_fingerprint, value=normalized, test=test)
                store.succeed(operation.id, {"plan": self._plan_result(plan)})
            except Exception:
                try:
                    store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
                except ManagementError:
                    pass
                self._audit(actual, "network.socks5.test", "socks5", "failed")
        try:
            self._start_worker(worker)
        except Exception as exc:
            store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True, operation_id=operation.id) from exc
        return operation

    def _plan_result(self, plan: _Plan) -> dict[str, Any]:
        value = self._public_plan(plan)
        result = asdict(value)
        result["createdAt"] = _rfc3339(plan.created_at)
        result["expiresAt"] = _rfc3339(plan.expires_at)
        return result

    def _commit(
        self,
        context: ManagementContext | None,
        plan_id: str,
        *,
        kind: str,
        force: bool,
        expected_revision: str | None,
    ) -> NetworkSettings:
        capability = Capability.SECRETS_WRITE if kind == "socks5" else Capability.WRITE
        actual = self._write(context, capability)
        action = f"network.{kind}.commit"
        try:
            with self._lock:
                plan = self._lookup(actual, plan_id, kind)
                if not plan.passed and not force:
                    raise ManagementError(ManagementErrorCode.CONFIRMATION_REQUIRED, "The tested value failed; force=true is required")
                if plan.passed and force:
                    raise self._validation("force", "force_not_applicable", "force is only valid for a failed tested result")
                with self.gateway.serialized_updates():
                    current = self._network()
                    if (
                        current.revision != plan.revision
                        or self._network_authority_fingerprint(self.gateway.config_get()) != plan.authority_fingerprint
                    ):
                        raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
                    self._check_revision(expected_revision, current.revision)
                    if kind == "dns":
                        self.gateway.save_dns(list(plan.value))
                    else:
                        self.gateway.save_socks5(str(plan.value), enabled=True)
                self._plans[plan.id] = replace(plan, state=PlanState.COMMITTED)
            result = self._network()
        except ManagementError:
            self._audit(actual, action, plan_id, "failed")
            raise
        except Exception as exc:
            self._audit(actual, action, plan_id, "failed")
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        self._audit(actual, action, plan_id, "succeeded")
        return result

    def commit_dns(self, context, plan_id: str, *, force: bool, expected_revision=None) -> NetworkSettings:
        return self._commit(context, plan_id, kind="dns", force=force, expected_revision=expected_revision)

    def commit_socks5(self, context, plan_id: str, *, force: bool, expected_revision=None) -> NetworkSettings:
        return self._commit(context, plan_id, kind="socks5", force=force, expected_revision=expected_revision)

    def sync_system_dns(self, context, *, expected_revision=None) -> NetworkSettings:
        actual = self._write(context, Capability.WRITE)
        try:
            with self.gateway.serialized_updates():
                current = self._network()
                self._check_revision(expected_revision, current.revision)
                self.gateway.sync_system_dns()
            result = self._network()
        except ManagementError:
            self._audit(actual, "network.dns.sync", "dns", "failed")
            raise
        except Exception as exc:
            self._audit(actual, "network.dns.sync", "dns", "failed")
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        self._audit(actual, "network.dns.sync", "dns", "succeeded")
        return result

    def list_dns_cache(self, context, *, page: int, page_size: int) -> DnsCachePage:
        self._read(context)
        try:
            rows = list(self.gateway.dns_cache())
        except Exception as exc:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        items = []
        for row in rows:
            expires = _utc(row.get("expires_at_epoch"))
            if expires is None:
                continue
            items.append(DnsCacheEntry(
                host=str(sanitize_credentials(row.get("host") or "")),
                family=self._safe_int(row.get("family"), 0),
                servers=tuple(_safe_dns_server(item) for item in row.get("servers") or []),
                ips=tuple(str(item) for item in row.get("ips") or []),
                expiresAt=expires,
                ttlRemainingSeconds=max(0, self._safe_int(row.get("ttl_remaining_seconds"), 0)),
            ))
        start = (page - 1) * page_size
        revision = stable_revision([asdict(item) for item in items])
        return DnsCachePage(tuple(items[start:start + page_size]), page, page_size, len(items), revision)

    def clear_dns_cache(self, context) -> None:
        actual = self._write(context, Capability.DESTRUCTIVE)
        try:
            self.gateway.clear_dns_cache()
        except Exception as exc:
            self._audit(actual, "network.dns.cache.clear", "dns-cache", "failed")
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        self._audit(actual, "network.dns.cache.clear", "dns-cache", "succeeded")

    def update_socks5_state(self, context, enabled: bool, *, expected_revision=None) -> NetworkSettings:
        actual = self._write(context, Capability.WRITE)
        if type(enabled) is not bool:
            raise self._validation("enabled", "bool_type", "A boolean is required")
        try:
            with self.gateway.serialized_updates():
                current = self._network()
                self._check_revision(expected_revision, current.revision)
                raw = self.gateway.config_get().get("network") or {}
                url = str((raw.get("socks5") or {}).get("url") or "").strip()
                if enabled and not url:
                    raise self._validation("enabled", "socks5_not_configured", "Configure and test a SOCKS5 URL first")
                self.gateway.set_socks5_enabled(enabled)
            result = self._network()
        except ManagementError:
            self._audit(actual, "network.socks5.state.update", "socks5", "failed")
            raise
        except Exception as exc:
            self._audit(actual, "network.socks5.state.update", "socks5", "failed")
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        self._audit(actual, "network.socks5.state.update", "socks5", "succeeded")
        return result

    def _monitor(self) -> NetworkMonitorSettings:
        try:
            raw = self.gateway.monitor_config()
        except Exception as exc:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        core = raw.get("core") if isinstance(raw.get("core"), Mapping) else {}
        channels = raw.get("channels") if isinstance(raw.get("channels"), Mapping) else {}
        by_key = channels.get("byKey") if isinstance(channels.get("byKey"), Mapping) else {}
        by_channel = {key: bool(by_key.get(key, False)) for key in self._api_channel_ids()}
        values = {
            "enabled": bool(raw.get("enabled", True)),
            "intervalSeconds": max(5, self._safe_int(raw.get("intervalSeconds"), 60)),
            "dns": bool(raw.get("dns", False)),
            "socks5": bool(raw.get("socks5", False)),
            "core": MonitorCoreSettings(**{key: bool(core.get(key, False)) for key in ("openai", "claude", "cloudflare")}),
            "channels": MonitorChannelSettings(enabled=bool(channels.get("enabled", False)), byChannel=by_channel),
        }
        public = {key: asdict(value) if hasattr(value, "__dataclass_fields__") else value for key, value in values.items()}
        return NetworkMonitorSettings(**values, revision=stable_revision(public))

    def get_monitor(self, context) -> NetworkMonitorSettings:
        self._read(context)
        return self._monitor()

    def update_monitor(self, context, patch: Mapping[str, Any], *, expected_revision=None) -> NetworkMonitorSettings:
        actual = self._write(context, Capability.WRITE)
        action = "network.monitor.update"
        allowed = {"enabled", "intervalSeconds", "dns", "socks5", "core", "channels"}
        unknown = sorted(set(patch) - allowed)
        if unknown:
            raise ManagementError(ManagementErrorCode.VALIDATION_FAILED, fields=tuple(ErrorField(key, "extra_forbidden", "Unknown field") for key in unknown))
        if not patch:
            raise self._validation("body", "empty_patch", "At least one field is required")
        for key in ("enabled", "dns", "socks5"):
            if key in patch and type(patch[key]) is not bool:
                raise self._validation(key, "bool_type", "A boolean is required")
        if "intervalSeconds" in patch and (isinstance(patch["intervalSeconds"], bool) or not isinstance(patch["intervalSeconds"], int) or patch["intervalSeconds"] < 5):
            raise self._validation("intervalSeconds", "greater_than_equal", "intervalSeconds must be at least 5")
        core_patch = patch.get("core") if "core" in patch else None
        if "core" in patch and not isinstance(core_patch, Mapping):
            raise self._validation("core", "dict_type", "An object is required")
        if core_patch is not None:
            if not isinstance(core_patch, Mapping): raise self._validation("core", "dict_type", "An object is required")
            unknown_core = sorted(set(core_patch) - {"openai", "claude", "cloudflare"})
            if unknown_core: raise self._validation("core", "extra_forbidden", "Unknown core target")
            if any(type(value) is not bool for value in core_patch.values()): raise self._validation("core", "bool_type", "Boolean target values are required")
        channels_patch = patch.get("channels") if "channels" in patch else None
        if "channels" in patch and not isinstance(channels_patch, Mapping):
            raise self._validation("channels", "dict_type", "An object is required")
        by_channel = None
        if channels_patch is not None:
            if not isinstance(channels_patch, Mapping): raise self._validation("channels", "dict_type", "An object is required")
            unknown_channels = sorted(set(channels_patch) - {"enabled", "byChannel"})
            if unknown_channels: raise self._validation("channels", "extra_forbidden", "Unknown channel setting")
            if "enabled" in channels_patch and type(channels_patch["enabled"]) is not bool: raise self._validation("channels.enabled", "bool_type", "A boolean is required")
            if "byChannel" in channels_patch:
                by_channel = channels_patch["byChannel"]
                if not isinstance(by_channel, Mapping): raise self._validation("channels.byChannel", "dict_type", "An object is required")
                known = set(self._api_channel_ids())
                unknown_ids = [str(key) for key in by_channel if str(key) not in known]
                if unknown_ids: raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND, fields=tuple(ErrorField(f"channels.byChannel.{key}", "UNKNOWN_CHANNEL", "Unknown canonical channel ID") for key in unknown_ids))
                if any(type(value) is not bool for value in by_channel.values()): raise self._validation("channels.byChannel", "bool_type", "Boolean channel values are required")

        def mutate(mon):
            for key in ("enabled", "intervalSeconds", "dns", "socks5"):
                if key in patch: mon[key] = patch[key]
            if core_patch is not None: mon.setdefault("core", {}).update(core_patch)
            if channels_patch is not None:
                target = mon.setdefault("channels", {"enabled": False, "byKey": {}})
                if "enabled" in channels_patch: target["enabled"] = channels_patch["enabled"]
                if by_channel is not None: target.setdefault("byKey", {}).update({str(key): value for key, value in by_channel.items()})
        try:
            with self.gateway.monitor_transaction():
                current = self._monitor()
                self._check_revision(expected_revision, current.revision)
                self.gateway.update_monitor(mutate)
            result = self._monitor()
        except ManagementError:
            self._audit(actual, action, "monitor", "failed")
            raise
        except Exception as exc:
            self._audit(actual, action, "monitor", "failed")
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        self._audit(actual, action, "monitor", "succeeded")
        return result

    def list_checks(self, context, *, page: int, page_size: int) -> NetworkCheckPage:
        self._read(context)
        try:
            raw = self.gateway.checks()
        except Exception as exc:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        items = []
        for row in raw:
            checked = row.get("checked_at")
            try:
                checked_at = _utc(float(checked) / 1000) if checked is not None else None
            except (TypeError, ValueError, OverflowError):
                checked_at = None
            items.append(NetworkCheck(
                key=str(row.get("key") or ""), label=str(sanitize_credentials(row.get("label") or "")),
                category=str(row.get("category") or ""), ok=bool(row.get("ok")),
                detail=str(sanitize_credentials(row.get("detail") or "")),
                latencyMilliseconds=(self._safe_int(row.get("latency_ms"), 0) if row.get("latency_ms") is not None else None),
                checkedAt=checked_at,
            ))
        start = (page - 1) * page_size
        return NetworkCheckPage(tuple(items[start:start + page_size]), page, page_size, len(items), stable_revision([asdict(item) for item in items]))

    def run_monitor(self, context, *, operations: OperationStore | None = None) -> ManagementOperation:
        actual = self._write(context, Capability.WRITE)
        store = self._operations(operations)
        operation = store.create(actual, kind="network.monitor.run", cancellable=False)
        def worker():
            try:
                store.mark_running(operation.id)
                raw = asyncio.run(self.gateway.run_monitor())
                formatter = getattr(self.gateway, "format_monitor_result", lambda item: item)
                result = [sanitize_credentials(formatter(item)) for item in raw]
                store.succeed(operation.id, {"checks": result})
                self._audit(actual, "network.monitor.run", "monitor", "succeeded")
            except Exception:
                try: store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
                except ManagementError: pass
                self._audit(actual, "network.monitor.run", "monitor", "failed")
        try:
            self._start_worker(worker)
        except Exception as exc:
            store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True, operation_id=operation.id) from exc
        return operation

    # Frozen Telegram compatibility methods. They share the same gateway and
    # validation boundary but intentionally retain Telegram's synchronous trace.
    def telegram_parse_dns(self, text: str) -> list[str]:
        parser = getattr(self.gateway, "parse_dns_text", None)
        return parser(text) if parser is not None else self.gateway.normalize_dns([text])

    def telegram_test_dns(self, context, servers: list[str]) -> dict[str, Any]:
        self._write(context, Capability.WRITE)
        return self.gateway.test_dns(servers)

    def telegram_normalize_socks5(self, url: str):
        return self.gateway.normalize_socks5(url)

    async def telegram_test_socks5(self, context, url: str) -> dict[str, Any]:
        self._write(context, Capability.SECRETS_WRITE)
        return await self.gateway.test_socks5(url)

    def telegram_save_dns(self, context, servers: list[str], test: Mapping[str, Any], *, force: bool) -> None:
        self._write(context, Capability.WRITE)
        if not test.get("ok") and not force:
            raise ManagementError(ManagementErrorCode.CONFIRMATION_REQUIRED)
        self.gateway.save_dns(servers)

    def telegram_save_socks5(self, context, url: str, test: Mapping[str, Any], *, force: bool) -> str:
        self._write(context, Capability.SECRETS_WRITE)
        if not test.get("ok") and not force:
            raise ManagementError(ManagementErrorCode.CONFIRMATION_REQUIRED)
        return self.gateway.save_socks5(url, enabled=True)

    def telegram_sync_dns(self, context) -> list[str]:
        self._write(context, Capability.WRITE)
        return self.gateway.sync_system_dns()

    def telegram_clear_dns_cache(self, context) -> None:
        self._write(context, Capability.DESTRUCTIVE)
        self.gateway.clear_dns_cache()

    def telegram_set_socks5_enabled(self, context, enabled: bool) -> None:
        self._write(context, Capability.WRITE)
        self.gateway.set_socks5_enabled(enabled)

    def telegram_update_monitor(self, context, mutator: Callable[[dict[str, Any]], None]) -> None:
        self._write(context, Capability.WRITE)
        self.gateway.update_monitor(mutator)

    def telegram_set_monitor_channel(self, context, channel_id: str, enabled: bool) -> None:
        self._write(context, Capability.WRITE)
        self.gateway.set_monitor_channel(channel_id, enabled)

    async def telegram_run_monitor(self, context):
        self._write(context, Capability.WRITE)
        return await self.gateway.run_monitor()


DEFAULT_NETWORK_CONTROL = NetworkControl()

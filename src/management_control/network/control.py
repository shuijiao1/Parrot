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

from src.management_auth import Capability
from src.management_control.context import AuditSink, ManagementContext
from src.management_control.errors import ErrorField, ManagementError, ManagementErrorCode
from src.management_control.models.common import DomainControl, stable_revision
from src.management_control.operations import (
    ManagementOperation,
    OperationStore,
    PublicIdentifier,
)

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
from .security import (
    MONITOR_PUBLIC_IDENTIFIER_KEYS,
    safe_dns_server,
    safe_network_url,
    sanitize_public_network,
    sanitize_public_network_text,
)


_MONITOR_CATEGORIES = frozenset({"dns", "socks5", "channel", "core"})


def _mark_monitor_operation_identifiers(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): PublicIdentifier(str(item or ""))
            if str(key) == "key"
            else _mark_monitor_operation_identifiers(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mark_monitor_operation_identifiers(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_mark_monitor_operation_identifiers(item) for item in value)
    return value


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

    @staticmethod
    def _dependency(callable_):
        """Translate a dependency failure without retaining its raw exception chain."""
        failed = False
        try:
            value = callable_()
        except Exception:
            failed = True
        if failed:
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        return value

    def _channels(self) -> list[Any]:
        return self._dependency(lambda: list(self.gateway.channels()))

    def _api_channel_ids(self) -> tuple[str, ...]:
        def project() -> tuple[str, ...]:
            cfg = self.gateway.config_get()
            values = []
            for entry in cfg.get("channels") or []:
                if not isinstance(entry, Mapping):
                    continue
                name = str(entry.get("name") or "").strip()
                if name:
                    values.append("api:" + name)
            return tuple(values)

        return self._dependency(project)

    def _network(self, cfg: Mapping[str, Any] | None = None) -> NetworkSettings:
        cfg = self._dependency(self.gateway.config_get) if cfg is None else cfg
        net = cfg.get("network") if isinstance(cfg.get("network"), Mapping) else {}
        dns = net.get("dns") if isinstance(net.get("dns"), Mapping) else {}
        socks = net.get("socks5") if isinstance(net.get("socks5"), Mapping) else {}
        proxies = net.get("proxies") if isinstance(net.get("proxies"), Mapping) else {}
        groups = net.get("groups") if isinstance(net.get("groups"), Mapping) else {}
        routing = net.get("routing") if isinstance(net.get("routing"), Mapping) else {}
        raw_servers = dns.get("servers") or ["8.8.8.8"]
        servers = tuple(safe_dns_server(item) for item in raw_servers)
        raw_url = str(socks.get("url") or "").strip()
        masked = safe_network_url(raw_url, mask_user=True, drop_path=True) if raw_url else None
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
                defaultRoute=sanitize_public_network_text(routing.get("default") or "direct"),
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
        return self._dependency(self._network)

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
        clean = sanitize_public_network(copy.deepcopy(dict(test)))
        if kind == "socks5":
            clean.pop("url", None)
            clean.pop("display_url", None)
            clean.pop("displayUrl", None)
        return clean

    @staticmethod
    def _public_monitor_result(value: Mapping[str, Any]) -> dict[str, Any]:
        """Sanitize untrusted fields without treating public DTO names as secrets."""
        clean = sanitize_public_network(
            copy.deepcopy(dict(value)),
            public_identifier_keys=MONITOR_PUBLIC_IDENTIFIER_KEYS,
        )
        clean = _mark_monitor_operation_identifiers(clean)
        category = str(clean.get("category") or "")
        if category not in _MONITOR_CATEGORIES:
            raise NetworkControl._validation(
                "category", "unsupported_value", "Unsupported monitor category",
            )
        clean["category"] = category
        return clean

    def _public_plan(self, plan: _Plan) -> NetworkTestPlan:
        tested = (
            {"servers": tuple(safe_dns_server(item) for item in plan.value)}
            if plan.kind == "dns"
            else {"configured": True, "maskedUrl": safe_network_url(str(plan.value), mask_user=True, drop_path=True)}
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
        invalid = False
        try:
            normalized = self.gateway.normalize_dns(list(servers))
        except Exception:
            invalid = True
        if invalid:
            # Raise outside the handler so raw URL credentials cannot survive in
            # ManagementError.__cause__ or __context__.
            self._audit(actual, "network.dns.test", "dns", "failed")
            raise self._validation(
                "servers", "invalid_dns", "DNS server list is invalid",
            )
        def authority_snapshot():
            with self.gateway.serialized_updates():
                cfg = self.gateway.config_get()
                return (
                    self._network(cfg).revision,
                    self._network_authority_fingerprint(cfg),
                )

        setup_error: ManagementError | None = None
        setup_failed = False
        try:
            revision, authority_fingerprint = self._dependency(authority_snapshot)
            store = self._operations(operations)
            operation = store.create(
                actual, kind="network.dns.test", cancellable=False,
            )
        except ManagementError as exc:
            setup_error = exc
        except Exception:
            setup_failed = True
        if setup_failed:
            self._audit(actual, "network.dns.test", "dns", "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if setup_error is not None:
            self._audit(actual, "network.dns.test", "dns", "failed")
            raise setup_error

        def worker() -> None:
            plan = None
            try:
                store.mark_running(operation.id)
                test = self.gateway.test_dns(list(normalized))
                plan = self._publish_plan(
                    actual, kind="dns", revision=revision,
                    authority_fingerprint=authority_fingerprint,
                    value=normalized, test=test,
                )
                store.succeed(operation.id, {"plan": self._plan_result(plan)})
                self._audit(actual, "network.dns.test", plan.id, "succeeded")
            except Exception:
                if plan is not None:
                    with self._lock:
                        self._plans.pop(plan.id, None)
                try:
                    store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
                except ManagementError:
                    pass
                self._audit(actual, "network.dns.test", "dns", "failed")
        launch_failed = False
        try:
            self._start_worker(worker)
        except Exception:
            store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
            self._audit(actual, "network.dns.test", "dns", "failed")
            launch_failed = True
        if launch_failed:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True, operation_id=operation.id)
        return operation

    def start_socks5_test(
        self, context: ManagementContext | None, url: str, *, operations: OperationStore | None = None,
    ) -> ManagementOperation:
        actual = self._write(context, Capability.SECRETS_WRITE)
        invalid = False
        try:
            normalized = self.gateway.normalize_socks5(url).url
        except Exception:
            invalid = True
        if invalid:
            self._audit(actual, "network.socks5.test", "socks5", "failed")
            raise self._validation(
                "url", "invalid_socks5", "SOCKS5 URL is invalid",
            )
        def authority_snapshot():
            with self.gateway.serialized_updates():
                cfg = self.gateway.config_get()
                return (
                    self._network(cfg).revision,
                    self._network_authority_fingerprint(cfg),
                )

        setup_error: ManagementError | None = None
        setup_failed = False
        try:
            revision, authority_fingerprint = self._dependency(authority_snapshot)
            store = self._operations(operations)
            operation = store.create(
                actual, kind="network.socks5.test", cancellable=False,
            )
        except ManagementError as exc:
            setup_error = exc
        except Exception:
            setup_failed = True
        if setup_failed:
            self._audit(actual, "network.socks5.test", "socks5", "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if setup_error is not None:
            self._audit(actual, "network.socks5.test", "socks5", "failed")
            raise setup_error

        def worker() -> None:
            plan = None
            try:
                store.mark_running(operation.id)
                test = asyncio.run(self.gateway.test_socks5(normalized))
                plan = self._publish_plan(
                    actual, kind="socks5", revision=revision,
                    authority_fingerprint=authority_fingerprint,
                    value=normalized, test=test,
                )
                store.succeed(operation.id, {"plan": self._plan_result(plan)})
                self._audit(actual, "network.socks5.test", plan.id, "succeeded")
            except Exception:
                if plan is not None:
                    with self._lock:
                        self._plans.pop(plan.id, None)
                try:
                    store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
                except ManagementError:
                    pass
                self._audit(actual, "network.socks5.test", "socks5", "failed")
        launch_failed = False
        try:
            self._start_worker(worker)
        except Exception:
            store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
            self._audit(actual, "network.socks5.test", "socks5", "failed")
            launch_failed = True
        if launch_failed:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True, operation_id=operation.id)
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
        public_error: ManagementError | None = None
        dependency_failed = False
        transaction_complete = False
        revision_conflict = False
        result = None
        try:
            with self._lock:
                plan = self._lookup(actual, plan_id, kind)
                if not plan.passed and not force:
                    raise ManagementError(
                        ManagementErrorCode.CONFIRMATION_REQUIRED,
                        "The tested value failed; force=true is required",
                    )
                if plan.passed and force:
                    raise self._validation(
                        "force", "force_not_applicable",
                        "force is only valid for a failed tested result",
                    )

                def commit_authority() -> None:
                    nonlocal revision_conflict, transaction_complete
                    with self.gateway.serialized_updates():
                        current = self._network()
                        revision_conflict = (
                            current.revision != plan.revision
                            or self._network_authority_fingerprint(
                                self.gateway.config_get(),
                            ) != plan.authority_fingerprint
                            or (
                                expected_revision is not None
                                and expected_revision != current.revision
                            )
                        )
                        if not revision_conflict:
                            if kind == "dns":
                                self.gateway.save_dns(list(plan.value))
                            else:
                                self.gateway.save_socks5(
                                    str(plan.value), enabled=True,
                                )
                        transaction_complete = True

                self._dependency(commit_authority)
                if not transaction_complete:
                    dependency_failed = True
                elif revision_conflict:
                    public_error = ManagementError(
                        ManagementErrorCode.REVISION_CONFLICT,
                    )
                else:
                    self._plans[plan.id] = replace(
                        plan, state=PlanState.COMMITTED,
                    )
            if public_error is None and not dependency_failed:
                result = self._dependency(self._network)
        except ManagementError as exc:
            public_error = exc
        except Exception:
            dependency_failed = True
        if dependency_failed or (public_error is None and result is None):
            self._audit(actual, action, plan_id, "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if public_error is not None:
            self._audit(actual, action, plan_id, "failed")
            raise public_error
        self._audit(actual, action, plan_id, "succeeded")
        return result

    def commit_dns(self, context, plan_id: str, *, force: bool, expected_revision=None) -> NetworkSettings:
        return self._commit(context, plan_id, kind="dns", force=force, expected_revision=expected_revision)

    def commit_socks5(self, context, plan_id: str, *, force: bool, expected_revision=None) -> NetworkSettings:
        return self._commit(context, plan_id, kind="socks5", force=force, expected_revision=expected_revision)

    def sync_system_dns(self, context, *, expected_revision=None) -> NetworkSettings:
        actual = self._write(context, Capability.WRITE)
        action = "network.dns.sync"
        dependency_failed = False
        transaction_complete = False
        revision_conflict = False
        result = None

        def synchronize() -> None:
            nonlocal revision_conflict, transaction_complete
            with self.gateway.serialized_updates():
                current = self._network()
                revision_conflict = (
                    expected_revision is not None
                    and expected_revision != current.revision
                )
                if not revision_conflict:
                    self.gateway.sync_system_dns()
                transaction_complete = True

        try:
            self._dependency(synchronize)
            if not transaction_complete:
                dependency_failed = True
            elif not revision_conflict:
                result = self._dependency(self._network)
        except Exception:
            dependency_failed = True
        if dependency_failed or (not revision_conflict and result is None):
            self._audit(actual, action, "dns", "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if revision_conflict:
            self._audit(actual, action, "dns", "failed")
            raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
        self._audit(actual, action, "dns", "succeeded")
        return result

    def list_dns_cache(self, context, *, page: int, page_size: int) -> DnsCachePage:
        self._read(context)

        def project() -> DnsCachePage:
            rows = list(self.gateway.dns_cache())
            items = []
            for row in rows:
                expires = _utc(row.get("expires_at_epoch"))
                if expires is None:
                    continue
                items.append(DnsCacheEntry(
                    host=sanitize_public_network_text(row.get("host") or ""),
                    family=self._safe_int(row.get("family"), 0),
                    servers=tuple(safe_dns_server(item) for item in row.get("servers") or []),
                    ips=tuple(sanitize_public_network_text(item) for item in row.get("ips") or []),
                    expiresAt=expires,
                    ttlRemainingSeconds=max(0, self._safe_int(row.get("ttl_remaining_seconds"), 0)),
                ))
            start = (page - 1) * page_size
            revision = stable_revision([asdict(item) for item in items])
            return DnsCachePage(
                tuple(items[start:start + page_size]), page, page_size,
                len(items), revision,
            )

        return self._dependency(project)

    def clear_dns_cache(self, context) -> None:
        actual = self._write(context, Capability.DESTRUCTIVE)
        try:
            self._dependency(self.gateway.clear_dns_cache)
        except ManagementError:
            self._audit(actual, "network.dns.cache.clear", "dns-cache", "failed")
            raise
        self._audit(actual, "network.dns.cache.clear", "dns-cache", "succeeded")

    def update_socks5_state(self, context, enabled: bool, *, expected_revision=None) -> NetworkSettings:
        actual = self._write(context, Capability.WRITE)
        action = "network.socks5.state.update"
        if type(enabled) is not bool:
            raise self._validation("enabled", "bool_type", "A boolean is required")
        dependency_failed = False
        transaction_complete = False
        revision_conflict = False
        not_configured = False
        result = None

        def update_state() -> None:
            nonlocal revision_conflict, not_configured, transaction_complete
            with self.gateway.serialized_updates():
                current = self._network()
                revision_conflict = (
                    expected_revision is not None
                    and expected_revision != current.revision
                )
                if not revision_conflict:
                    raw = self.gateway.config_get().get("network") or {}
                    url = str((raw.get("socks5") or {}).get("url") or "").strip()
                    not_configured = enabled and not url
                    if not not_configured:
                        self.gateway.set_socks5_enabled(enabled)
                transaction_complete = True

        try:
            self._dependency(update_state)
            if not transaction_complete:
                dependency_failed = True
            elif not revision_conflict and not not_configured:
                result = self._dependency(self._network)
        except Exception:
            dependency_failed = True
        if dependency_failed or (
            not revision_conflict and not not_configured and result is None
        ):
            self._audit(actual, action, "socks5", "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if revision_conflict:
            self._audit(actual, action, "socks5", "failed")
            raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
        if not_configured:
            self._audit(actual, action, "socks5", "failed")
            raise self._validation(
                "enabled", "socks5_not_configured",
                "Configure and test a SOCKS5 URL first",
            )
        self._audit(actual, action, "socks5", "succeeded")
        return result

    def _monitor(self) -> NetworkMonitorSettings:
        raw = self._dependency(self.gateway.monitor_config)
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
        return self._dependency(self._monitor)

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
        semantic_change = any(key in patch for key in ("enabled", "intervalSeconds", "dns", "socks5"))
        semantic_change = semantic_change or bool(core_patch)
        semantic_change = semantic_change or bool(channels_patch and (
            "enabled" in channels_patch or bool(channels_patch.get("byChannel"))
        ))
        if not semantic_change:
            raise self._validation("body", "empty_patch", "At least one field is required")

        def mutate(mon):
            for key in ("enabled", "intervalSeconds", "dns", "socks5"):
                if key in patch: mon[key] = patch[key]
            if core_patch is not None: mon.setdefault("core", {}).update(core_patch)
            if channels_patch is not None:
                target = mon.setdefault("channels", {"enabled": False, "byKey": {}})
                if "enabled" in channels_patch: target["enabled"] = channels_patch["enabled"]
                if by_channel is not None: target.setdefault("byKey", {}).update({str(key): value for key, value in by_channel.items()})
        dependency_failed = False
        transaction_complete = False
        revision_conflict = False
        result = None

        def update_authority() -> None:
            nonlocal revision_conflict, transaction_complete
            with self.gateway.monitor_transaction():
                current = self._monitor()
                revision_conflict = (
                    expected_revision is not None
                    and expected_revision != current.revision
                )
                if not revision_conflict:
                    self.gateway.update_monitor(mutate)
                transaction_complete = True

        try:
            self._dependency(update_authority)
            if not transaction_complete:
                dependency_failed = True
            elif not revision_conflict:
                result = self._dependency(self._monitor)
        except Exception:
            dependency_failed = True
        if dependency_failed or (not revision_conflict and result is None):
            self._audit(actual, action, "monitor", "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if revision_conflict:
            self._audit(actual, action, "monitor", "failed")
            raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
        self._audit(actual, action, "monitor", "succeeded")
        return result

    def list_checks(self, context, *, page: int, page_size: int) -> NetworkCheckPage:
        self._read(context)
        invalid_category = False

        def project() -> NetworkCheckPage | None:
            nonlocal invalid_category
            raw = self.gateway.checks()
            items = []
            for row in raw:
                checked = row.get("checked_at")
                try:
                    checked_at = _utc(float(checked) / 1000) if checked is not None else None
                except (TypeError, ValueError, OverflowError):
                    checked_at = None
                category = str(row.get("category") or "")
                if category not in _MONITOR_CATEGORIES:
                    invalid_category = True
                    return None
                items.append(NetworkCheck(
                    key=str(row.get("key") or ""),
                    label=sanitize_public_network_text(row.get("label") or ""),
                    category=category, ok=bool(row.get("ok")),
                    detail=sanitize_public_network_text(row.get("detail") or ""),
                    latencyMilliseconds=(
                        self._safe_int(row.get("latency_ms"), 0)
                        if row.get("latency_ms") is not None else None
                    ),
                    checkedAt=checked_at,
                ))
            start = (page - 1) * page_size
            return NetworkCheckPage(
                tuple(items[start:start + page_size]), page, page_size,
                len(items), stable_revision([asdict(item) for item in items]),
            )

        result = self._dependency(project)
        if invalid_category:
            raise self._validation(
                "category", "unsupported_value", "Unsupported monitor category",
            )
        if result is None:
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        return result

    def run_monitor(self, context, *, operations: OperationStore | None = None) -> ManagementOperation:
        actual = self._write(context, Capability.WRITE)
        setup_error: ManagementError | None = None
        setup_failed = False
        try:
            store = self._operations(operations)
            operation = store.create(
                actual, kind="network.monitor.run", cancellable=False,
            )
        except ManagementError as exc:
            setup_error = exc
        except Exception:
            setup_failed = True
        if setup_failed:
            self._audit(actual, "network.monitor.run", "monitor", "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if setup_error is not None:
            self._audit(actual, "network.monitor.run", "monitor", "failed")
            raise setup_error

        def worker():
            try:
                store.mark_running(operation.id)
                raw = asyncio.run(self.gateway.run_monitor())
                formatter = getattr(self.gateway, "format_monitor_result", lambda item: item)
                result = [self._public_monitor_result(formatter(item)) for item in raw]
                store.succeed(operation.id, {"checks": result})
                self._audit(actual, "network.monitor.run", "monitor", "succeeded")
            except Exception:
                try: store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
                except ManagementError: pass
                self._audit(actual, "network.monitor.run", "monitor", "failed")
        launch_failed = False
        try:
            self._start_worker(worker)
        except Exception:
            store.fail(operation.id, code=ManagementErrorCode.DEPENDENCY_UNAVAILABLE, message=ManagementErrorCode.DEPENDENCY_UNAVAILABLE.value, retryable=True)
            self._audit(actual, "network.monitor.run", "monitor", "failed")
            launch_failed = True
        if launch_failed:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True, operation_id=operation.id)
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

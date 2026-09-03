"""Ordered, CAS-safe content blacklist use cases."""

from __future__ import annotations

from collections import OrderedDict
from contextlib import nullcontext
from typing import Any

from src import config as config_module
from src.channel import registry as registry_module
from src.management_auth import Capability
from src.management_control.context import AuditSink, ManagementContext
from src.management_control.errors import ManagementError, ManagementErrorCode
from src.management_control.models.common import DomainControl, stable_revision

from .models import ChannelBlacklist, ContentBlacklist


class ContentBlacklistControl(DomainControl):
    def __init__(
        self,
        *,
        config=config_module,
        registry=registry_module,
        audit_sink: AuditSink | None = None,
    ) -> None:
        super().__init__(audit_sink=audit_sink)
        self.config = config
        self.registry = registry

    def _channels(self) -> list[Any]:
        try:
            return list(self.registry.all_channels())
        except Exception as exc:
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc

    def _identity_transaction(self):
        lock = getattr(self.registry, "_lock", None)
        return lock if lock is not None else nullcontext()

    def _canonical(self, raw: str, *, allow_display_name: bool = False) -> str:
        value = str(raw or "").strip()
        channels = self._channels()
        exact = next((str(ch.key) for ch in channels if str(ch.key) == value), None)
        if exact is not None:
            return exact
        if allow_display_name:
            matches = [str(ch.key) for ch in channels if str(getattr(ch, "display_name", "")) == value]
            if len(matches) == 1:
                return matches[0]
        raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)

    def _snapshot(self, cfg: dict[str, Any] | None = None) -> ContentBlacklist:
        cfg = self.config.get() if cfg is None else cfg
        raw = cfg.get("contentBlacklist") or {}
        defaults = tuple(str(item) for item in (raw.get("default") or []) if str(item))
        by_channel = raw.get("byChannel") or {}
        live = self._channels()
        exact = {str(ch.key): str(ch.key) for ch in live}
        by_display: dict[str, list[str]] = {}
        for channel in live:
            by_display.setdefault(str(getattr(channel, "display_name", "")), []).append(str(channel.key))
        merged: OrderedDict[str, list[str]] = OrderedDict()
        for raw_id, raw_terms in by_channel.items():
            identifier = str(raw_id)
            canonical = exact.get(identifier)
            if canonical is None:
                matches = by_display.get(identifier) or []
                canonical = matches[0] if len(matches) == 1 else None
            if canonical is None:
                continue
            target = merged.setdefault(canonical, [])
            for raw_term in raw_terms or []:
                term = str(raw_term)
                if term and term not in target:
                    target.append(term)
        values = {
            "default": defaults,
            "byChannel": tuple(ChannelBlacklist(channelId=key, terms=tuple(terms)) for key, terms in merged.items() if terms),
        }
        return ContentBlacklist(**values, revision=self._revision(cfg))

    @staticmethod
    def _revision(cfg: dict[str, Any]) -> str:
        raw = cfg.get("contentBlacklist") or {}
        return stable_revision({
            "default": list(raw.get("default") or []),
            "byChannel": dict(raw.get("byChannel") or {}),
        })

    def get(self, context: ManagementContext | None) -> ContentBlacklist:
        self._read(context)
        return self._snapshot()

    @staticmethod
    def _term(raw: str, *, enforce_limit: bool = True) -> str:
        value = str(raw or "").strip()
        if not value:
            raise ContentBlacklistControl._validation("term", "min_length", "Term must not be empty")
        if enforce_limit and len(value) > 200:
            raise ContentBlacklistControl._validation("term", "max_length", "Term may contain at most 200 characters")
        return value

    def _mutate(
        self,
        context: ManagementContext | None,
        *,
        action: str,
        target: str,
        expected_revision: str | None,
        capability: Capability,
        mutate,
    ) -> ContentBlacklist:
        actual = self._write(context, capability)
        try:
            with self.config.serialized_updates():
                self._check_revision(expected_revision, self._revision(self.config.get()))
                self.config.update(mutate)
            result = self._snapshot(self.config.get())
        except ManagementError:
            self._audit(actual, action, target, "failed")
            raise
        except Exception as exc:
            self._audit(actual, action, target, "failed")
            raise ManagementError(ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True) from exc
        self._audit(actual, action, target, "succeeded")
        return result

    def add_default(
        self, context: ManagementContext | None, term: str, *, expected_revision: str | None = None,
    ) -> ContentBlacklist:
        self._write(context, Capability.WRITE)
        value = self._term(term)
        def mutate(cfg):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("default", [])
            if value not in terms:
                terms.append(value)
        return self._mutate(context, action="content_blacklist.default.add", target="default", expected_revision=expected_revision, capability=Capability.WRITE, mutate=mutate)

    def delete_default(
        self, context: ManagementContext | None, term: str, *, expected_revision: str | None = None,
    ) -> ContentBlacklist:
        self._write(context, Capability.DESTRUCTIVE)
        value = self._term(term)
        def mutate(cfg):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("default", [])
            if value in terms:
                terms.remove(value)
        return self._mutate(context, action="content_blacklist.default.delete", target="default", expected_revision=expected_revision, capability=Capability.DESTRUCTIVE, mutate=mutate)

    def add_channel(
        self,
        context: ManagementContext | None,
        channel_id: str,
        term: str,
        *,
        expected_revision: str | None = None,
    ) -> ContentBlacklist:
        self._write(context, Capability.WRITE)
        value = self._term(term)
        with self._identity_transaction():
            canonical = self._canonical(channel_id)
            def mutate(cfg):
                terms = cfg.setdefault("contentBlacklist", {}).setdefault("byChannel", {}).setdefault(canonical, [])
                if value not in terms:
                    terms.append(value)
            return self._mutate(context, action="content_blacklist.channel.add", target=canonical, expected_revision=expected_revision, capability=Capability.WRITE, mutate=mutate)

    def delete_channel(
        self,
        context: ManagementContext | None,
        channel_id: str,
        term: str,
        *,
        expected_revision: str | None = None,
    ) -> ContentBlacklist:
        self._write(context, Capability.DESTRUCTIVE)
        value = self._term(term)
        with self._identity_transaction():
            canonical = self._canonical(channel_id)
            channel = next((ch for ch in self._channels() if str(ch.key) == canonical), None)
            display = str(getattr(channel, "display_name", "")) if channel is not None else ""
            def mutate(cfg):
                by_channel = cfg.setdefault("contentBlacklist", {}).setdefault("byChannel", {})
                keys = [canonical]
                if display and display not in keys:
                    keys.append(display)
                for key in keys:
                    terms = by_channel.get(key)
                    if not isinstance(terms, list):
                        continue
                    while value in terms:
                        terms.remove(value)
                    if not terms:
                        by_channel.pop(key, None)
            return self._mutate(context, action="content_blacklist.channel.delete", target=canonical, expected_revision=expected_revision, capability=Capability.DESTRUCTIVE, mutate=mutate)

    # Telegram accepts a display name and historically does not require a live
    # channel.  Keep that adapter-only quirk while sharing the mutation itself.
    def add_telegram_channel(
        self, context: ManagementContext | None, channel_name: str, term: str,
    ) -> ContentBlacklist:
        self._write(context, Capability.WRITE)
        name = str(channel_name or "").strip()
        value = self._term(term, enforce_limit=False)
        if not name:
            raise self._validation("channel", "min_length", "Channel must not be empty")
        def mutate(cfg):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("byChannel", {}).setdefault(name, [])
            if value not in terms:
                terms.append(value)
        return self._mutate(context, action="content_blacklist.channel.add", target=name, expected_revision=None, capability=Capability.WRITE, mutate=mutate)


DEFAULT_CONTENT_BLACKLIST_CONTROL = ContentBlacklistControl()

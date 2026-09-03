"""Ordered, CAS-safe content blacklist use cases."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Iterable

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

    @staticmethod
    def _dependency(callable_):
        """Return a dependency result without retaining a raw failure chain."""
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

    def _channels(self) -> tuple[Any, ...]:
        return self._dependency(lambda: tuple(self.registry.all_channels()))

    @staticmethod
    def _channel_maps(channels: Iterable[Any]) -> tuple[dict[str, str], dict[str, list[str]]]:
        exact: dict[str, str] = {}
        by_display: dict[str, list[str]] = {}
        for channel in channels:
            key = str(channel.key)
            exact[key] = key
            by_display.setdefault(str(getattr(channel, "display_name", "")), []).append(key)
        return exact, by_display

    @classmethod
    def _project_channel_id(cls, raw: str, channels: Iterable[Any]) -> str:
        identifier = str(raw)
        exact, by_display = cls._channel_maps(channels)
        if identifier in exact:
            return exact[identifier]
        matches = by_display.get(identifier) or []
        return matches[0] if len(matches) == 1 else identifier

    @classmethod
    def _canonical_live(
        cls, raw: str, channels: Iterable[Any], *, allow_display_name: bool = False,
    ) -> str:
        value = str(raw or "").strip()
        exact, by_display = cls._channel_maps(channels)
        if value in exact:
            return exact[value]
        if allow_display_name:
            matches = by_display.get(value) or []
            if len(matches) == 1:
                return matches[0]
        raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)

    @classmethod
    def _projection(cls, cfg: dict[str, Any], channels: Iterable[Any]) -> dict[str, Any]:
        """Build exactly the ordered, public-effective GET payload without revision.

        Raw display-name aliases are folded into a unique live canonical ID.  Every
        other authority scope remains visible as an orphan, in source order, so it
        can still be addressed and removed.  A list-of-objects is intentional:
        ``stable_revision`` may sort object keys, but must retain scope order.
        """
        raw = cfg.get("contentBlacklist") or {}
        defaults = [str(item) for item in (raw.get("default") or []) if str(item)]
        by_channel = raw.get("byChannel") or {}
        if not isinstance(by_channel, dict):
            by_channel = {}
        merged: OrderedDict[str, list[str]] = OrderedDict()
        for raw_id, raw_terms in by_channel.items():
            identifier = cls._project_channel_id(str(raw_id), channels)
            target = merged.setdefault(identifier, [])
            if not isinstance(raw_terms, (list, tuple)):
                continue
            for raw_term in raw_terms:
                term = str(raw_term)
                if term and term not in target:
                    target.append(term)
        return {
            "default": defaults,
            "byChannel": [
                {"channelId": key, "terms": terms}
                for key, terms in merged.items()
                if terms
            ],
        }

    @classmethod
    def _snapshot_from(cls, cfg: dict[str, Any], channels: Iterable[Any]) -> ContentBlacklist:
        public = cls._projection(cfg, channels)
        return ContentBlacklist(
            default=tuple(public["default"]),
            byChannel=tuple(
                ChannelBlacklist(
                    channelId=item["channelId"], terms=tuple(item["terms"]),
                )
                for item in public["byChannel"]
            ),
            revision=stable_revision(public),
        )

    def _snapshot(self) -> ContentBlacklist:
        # Management channel writers already use config -> registry.  Following
        # that order here avoids the former registry -> config AB-BA deadlock and
        # makes the config and visibility inputs one stable read point.
        failed = False
        result = None
        try:
            with self.config.serialized_updates():
                cfg = self._dependency(self.config.get)
                channels = self._channels()
                result = self._dependency(
                    lambda: self._snapshot_from(cfg, channels),
                )
        except Exception:
            failed = True
        if failed or result is None:
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        return result

    def get(self, context: ManagementContext | None) -> ContentBlacklist:
        self._read(context)
        return self._snapshot()

    @staticmethod
    def _term(raw: str, *, enforce_limit: bool = True) -> str:
        value = str(raw or "").strip()
        if not value:
            raise ContentBlacklistControl._validation(
                "term", "min_length", "Term must not be empty",
            )
        if enforce_limit and len(value) > 200:
            raise ContentBlacklistControl._validation(
                "term", "max_length", "Term may contain at most 200 characters",
            )
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
        dependency_failed = False
        revision_conflict = False
        domain_error: ManagementError | None = None
        result = None

        def guarded_mutate(cfg):
            nonlocal domain_error
            try:
                return mutate(cfg, channels)
            except ManagementError as exc:
                # Only errors raised by our mutation callback are public domain
                # errors. A ManagementError raised by config/transaction code is
                # still an untrusted dependency failure.
                domain_error = exc
                raise

        try:
            with self.config.serialized_updates():
                channels = self._channels()
                current = self._dependency(
                    lambda: self._snapshot_from(self.config.get(), channels),
                )
                revision_conflict = (
                    expected_revision is not None
                    and expected_revision != current.revision
                )
                if not revision_conflict:
                    try:
                        updated = self.config.update(guarded_mutate)
                    except Exception as exc:
                        if exc is not domain_error:
                            dependency_failed = True
                    if not dependency_failed and domain_error is None:
                        # Blacklist mutation cannot change channel visibility.
                        # Reusing this registry snapshot preserves config ->
                        # registry lock order and the committed public revision.
                        result = self._dependency(
                            lambda: self._snapshot_from(updated, channels),
                        )
        except Exception:
            dependency_failed = True
        if dependency_failed:
            self._audit(actual, action, target, "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        if revision_conflict:
            self._audit(actual, action, target, "failed")
            raise ManagementError(ManagementErrorCode.REVISION_CONFLICT)
        if domain_error is not None:
            self._audit(actual, action, target, "failed")
            raise domain_error
        if result is None:
            self._audit(actual, action, target, "failed")
            raise ManagementError(
                ManagementErrorCode.DEPENDENCY_UNAVAILABLE, retryable=True,
            )
        self._audit(actual, action, target, "succeeded")
        return result

    def add_default(
        self, context: ManagementContext | None, term: str, *, expected_revision: str | None = None,
    ) -> ContentBlacklist:
        value = self._term(term)

        def mutate(cfg, _channels):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("default", [])
            if value not in terms:
                terms.append(value)

        return self._mutate(
            context, action="content_blacklist.default.add", target="default",
            expected_revision=expected_revision, capability=Capability.WRITE,
            mutate=mutate,
        )

    def delete_default(
        self, context: ManagementContext | None, term: str, *, expected_revision: str | None = None,
    ) -> ContentBlacklist:
        value = self._term(term)

        def mutate(cfg, _channels):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("default", [])
            if value in terms:
                terms.remove(value)

        return self._mutate(
            context, action="content_blacklist.default.delete", target="default",
            expected_revision=expected_revision, capability=Capability.DESTRUCTIVE,
            mutate=mutate,
        )

    def add_channel(
        self,
        context: ManagementContext | None,
        channel_id: str,
        term: str,
        *,
        expected_revision: str | None = None,
    ) -> ContentBlacklist:
        value = self._term(term)
        requested = str(channel_id or "").strip()

        def mutate(cfg, channels):
            canonical = self._canonical_live(requested, channels)
            terms = (
                cfg.setdefault("contentBlacklist", {})
                .setdefault("byChannel", {})
                .setdefault(canonical, [])
            )
            if value not in terms:
                terms.append(value)

        return self._mutate(
            context, action="content_blacklist.channel.add", target=requested,
            expected_revision=expected_revision, capability=Capability.WRITE,
            mutate=mutate,
        )

    def delete_channel(
        self,
        context: ManagementContext | None,
        channel_id: str,
        term: str,
        *,
        expected_revision: str | None = None,
    ) -> ContentBlacklist:
        value = self._term(term)
        requested = str(channel_id or "").strip()

        def mutate(cfg, channels):
            by_channel = cfg.setdefault("contentBlacklist", {}).setdefault("byChannel", {})
            if not isinstance(by_channel, dict):
                raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
            projected_ids = {
                raw_key: self._project_channel_id(str(raw_key), channels)
                for raw_key in by_channel
            }
            if requested in projected_ids.values():
                target_id = requested
            elif requested in by_channel:
                target_id = projected_ids[requested]
            else:
                missing = False
                try:
                    target_id = self._canonical_live(
                        requested, channels, allow_display_name=True,
                    )
                except ManagementError:
                    missing = True
                if missing:
                    raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
            matching = [key for key, projected in projected_ids.items() if projected == target_id]
            if not matching:
                raise ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
            for key in matching:
                terms = by_channel.get(key)
                if not isinstance(terms, list):
                    continue
                while value in terms:
                    terms.remove(value)
                if not terms:
                    by_channel.pop(key, None)

        return self._mutate(
            context, action="content_blacklist.channel.delete", target=requested,
            expected_revision=expected_revision, capability=Capability.DESTRUCTIVE,
            mutate=mutate,
        )

    # Frozen Telegram commands deliberately return no public DTO.  Their v0.31.13
    # trace is one config write followed by state/UI work; no registry read or API
    # exception translation may be introduced after a successful write.
    def telegram_add_default(self, context: ManagementContext | None, term: str) -> None:
        self._write(context, Capability.WRITE)
        value = self._term(term)

        def mutate(cfg):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("default", [])
            if value not in terms:
                terms.append(value)

        self.config.update(mutate)

    def telegram_delete_default(self, context: ManagementContext | None, term: str) -> None:
        self._write(context, Capability.DESTRUCTIVE)
        value = self._term(term)

        def mutate(cfg):
            terms = cfg.setdefault("contentBlacklist", {}).setdefault("default", [])
            if value in terms:
                terms.remove(value)

        self.config.update(mutate)

    def add_telegram_channel(
        self, context: ManagementContext | None, channel_name: str, term: str,
    ) -> None:
        self._write(context, Capability.WRITE)
        name = str(channel_name or "").strip()
        value = self._term(term, enforce_limit=False)
        if not name:
            raise self._validation("channel", "min_length", "Channel must not be empty")

        def mutate(cfg):
            terms = (
                cfg.setdefault("contentBlacklist", {})
                .setdefault("byChannel", {})
                .setdefault(name, [])
            )
            if value not in terms:
                terms.append(value)

        self.config.update(mutate)


DEFAULT_CONTENT_BLACKLIST_CONTROL = ContentBlacklistControl()

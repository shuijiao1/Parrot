from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from unittest.mock import Mock

from src.management_control.composition import ObservabilityControls
from src.management_control.observability import MediaControl, StatsControl, StatusControl
from src.tests.management_observability_support import build_client


class MutableClock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class Authority:
    """Mutable, non-production authority consumed by real Control instances."""

    def __init__(self, artifact_path) -> None:
        self.clock = MutableClock(1_800_000_000.0)
        self.config_data = {
            "listen": {"host": "127.0.0.1", "port": 22123},
            "channels": [{"name": "api-one", "apiKey": "config-channel-secret"}],
            "oauthAccounts": [{"account_key": "account-one", "provider": "openai"}],
            "apiKeys": {"client-one": "downstream-key-secret"},
            "telegram": {"statsVisibility": {}},
            "affinity": {"cleanupIntervalSeconds": 300},
            "quotaMonitor": {"enabled": True, "intervalSeconds": 60},
            "cooldownRecovery": {"enabled": True, "intervalSeconds": 30},
        }
        self.channels = [
            SimpleNamespace(
                key="api:api-one", display_name="api-one", protocol="anthropic",
                type="api", enabled=True, disabled_reason=None,
                api_key="runtime-channel-secret",
            ),
            SimpleNamespace(
                key="oauth:account-one", display_name="oauth-one",
                protocol="openai-responses", type="oauth", enabled=True,
                disabled_reason=None, api_key="oauth-runtime-secret",
            ),
        ]
        self.cooldown_rows = [{
            "channel_key": "api:api-one", "model": "model-one", "error_count": 2,
            "cooldown_until": 1_900_000_000_000,
            "last_error_message": "authoritative cooldown reason", "quota": False,
        }]
        self.performance_rows = [{
            "channel_key": "api:api-one", "model": "model-one",
            "recent_requests": 10, "recent_success_count": 9,
            "score": 5, "avg_first_byte_ms": 20,
        }]
        self.quotas = {
            "account-one": {
                "account_key": "account-one", "codex_primary_used_pct": 91,
                "raw_data": '{"access_token":"quota-row-secret"}',
            },
            "deleted-account": {
                "account_key": "deleted-account", "seven_day_util": 99,
                "raw_data": '{"access_token":"orphan-row-secret"}',
            },
        }
        self.stats_total = 4
        self.stats_hidden = "stats-hidden-secret"
        self.oldest_wait_seconds = 1
        self.media_rows = [{
            "id": 1, "request_id": "media-request", "status": "success",
            "provider": "openai", "model": "image-model", "action": "generate",
            "media_type": "image", "progress": 100, "aspect_ratio": "1:1",
            "resolution": "1024x1024", "media_duration_seconds": None,
            "duration_ms": 100, "cost_usd_ticks": 3, "image_bytes": 8,
            "created_at": 1_800_000_000, "finished_at": 1_800_000_001,
            "error_message": None, "cache_paths": json.dumps([str(artifact_path)]),
            "expires_at": None, "account_key": "account-one",
            "account_email": "one@example.invalid", "upstream_request_id": "up-one",
            "upstream_status": "done", "http_status": 200,
            "prompt_preview": "public prompt", "api_key": "media-db-secret",
        }]
        self.mutation_calls: list[str] = []

    def mutation(self, name: str):
        self.mutation_calls.append(name)
        raise AssertionError(f"GET invoked mutation: {name}")


class ConfigAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def get(self):
        return copy.deepcopy(self.authority.config_data)

    def update(self, *_args, **_kwargs):
        self.authority.mutation("config.update")


class RegistryAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def all_channels(self):
        return list(self.authority.channels)

    def get_channel(self, key):
        return next((row for row in self.authority.channels if row.key == key), None)

    def rebuild_from_config(self):
        self.authority.mutation("registry.rebuild_from_config")


class CooldownAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def active_entries(self):
        return copy.deepcopy(self.authority.cooldown_rows)

    def clear(self, *_args, **_kwargs):
        self.authority.mutation("cooldown.clear")


class ScorerAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def snapshot(self):
        return copy.deepcopy(self.authority.performance_rows)


class AffinityAuthority:
    count = staticmethod(lambda: 0)
    client_count = staticmethod(lambda: 0)


class ChannelLimiterAuthority:
    totals = staticmethod(lambda: {"in_flight": 0, "waiting": 0, "tracked_channels": 1})
    snapshot = staticmethod(lambda: [{
        "channel_key": "api:api-one", "in_flight": 0, "max_concurrent": 2,
        "waiting": 0, "unlimited": False,
    }])


class ApiKeyLimiterAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    @staticmethod
    def totals():
        return {"in_flight": 0, "waiting": 1, "tracked_keys": 1}

    def snapshot(self):
        return [{
            "key_name": "client-one", "enabled": True, "in_flight": 0,
            "max_concurrent": 2, "max_queue": 3, "queue_wait_seconds": 10,
            "waiting": 1, "oldest_wait_seconds": self.authority.oldest_wait_seconds,
            "unlimited": False, "enabled_source": "key",
            "max_concurrent_source": "key", "max_queue_source": "key",
            "queue_wait_source": "key",
        }]


class OAuthAuthority:
    OAUTH_MODEL_SYNC_CHECK_INTERVAL_SECONDS = 60

    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def list_accounts(self):
        return copy.deepcopy(self.authority.config_data["oauthAccounts"])

    @staticmethod
    def get_account_key(account):
        return account.get("account_key")

    @staticmethod
    def provider_of(account):
        return account.get("provider") or "unknown"

    @staticmethod
    def fable_display_from_quota_row(_row):
        return None, None

    def ensure_quota_fresh_sync(self, *_args, **_kwargs):
        self.authority.mutation("oauth.ensure_quota_fresh_sync")


class QuotaErrorsAuthority:
    @staticmethod
    def active_quota_cooldown(row):
        return bool(row.get("quota"))


class StateAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority
        self.quota_keys: list[str] = []

    def quota_load(self, key):
        self.quota_keys.append(key)
        return copy.deepcopy(self.authority.quotas.get(key))

    def quota_load_all(self):
        raise AssertionError("overview must not scan orphan quota rows")

    @staticmethod
    def health():
        return {"started": True, "generation": {"runtime": 1}}

    def cleanup(self):
        self.authority.mutation("state.cleanup")


class LogDbAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def _snapshot(self):
        metrics = {
            "total": self.authority.stats_total,
            "success_count": self.authority.stats_total,
        }
        return {
            "summary": {
                "overall": metrics,
                "by_channel": {"api:api-one": metrics},
                "by_model": {"model-one": metrics},
            },
            "families": {"anthropic": {"overall": metrics}},
            "internal": {
                "credential": self.authority.stats_hidden,
                "generated_at": self.authority.clock(),
            },
        }

    def stats_summary(self, **_kwargs):
        return {"overall": {"total": self.authority.stats_total}}

    def stats_lifetime(self):
        return {"overall": {"total": self.authority.stats_total}}

    def stats_period_snapshot(self, _since):
        return copy.deepcopy(self._snapshot())

    @staticmethod
    def channels_by_requested_model(_since):
        return {"model-one": [{
            "key": "api:api-one", "count": 4, "type": "api",
            "upstream_protocol": "anthropic",
        }]}

    @staticmethod
    def recent_logs_count():
        return 1

    @staticmethod
    def recent_logs(_limit, offset=0):
        if offset:
            return []
        return [{
            "request_id": "request-one", "status": "success",
            "created_at": 1_800_000_000, "requested_model": "model-one",
            "final_channel_key": "api:api-one", "duration_ms": 25,
            "credential": "recent-call-secret",
        }]

    def management_logs_page(self, *, page=1, page_size=50):
        return self.recent_logs(page_size, offset=(page - 1) * page_size), self.recent_logs_count()

    def cleanup(self):
        self.authority.mutation("log_db.cleanup")


class MediaDbAuthority:
    def __init__(self, authority: Authority) -> None:
        self.authority = authority

    def count(self):
        return len(self.authority.media_rows)

    def recent(self, limit, offset=0):
        return copy.deepcopy(self.authority.media_rows[offset:offset + limit])

    def get_log(self, identifier):
        return copy.deepcopy(next(
            (row for row in self.authority.media_rows if row["id"] == identifier), None,
        ))

    def cleanup(self):
        self.authority.mutation("media_db.cleanup")


def _real_controls(authority: Authority) -> ObservabilityControls:
    config = ConfigAuthority(authority)
    registry = RegistryAuthority(authority)
    cooldown = CooldownAuthority(authority)
    scorer = ScorerAuthority(authority)
    oauth = OAuthAuthority(authority)
    state = StateAuthority(authority)
    logs = LogDbAuthority(authority)
    channel_limiter = ChannelLimiterAuthority()
    api_limiter = ApiKeyLimiterAuthority(authority)
    status = StatusControl(
        config=config, registry=registry, cooldown=cooldown, scorer=scorer,
        affinity=AffinityAuthority(), concurrency=channel_limiter,
        apikey_limiter=api_limiter, log_db=logs, oauth_manager=oauth,
        quota_errors=QuotaErrorsAuthority(), state_db=state,
        status_monitor=SimpleNamespace(snapshot_active=lambda: {}),
        now=authority.clock, service_started_at=authority.clock() - 100,
        version="s11-test",
    )
    stats = StatsControl(
        log_db=logs, config=config, concurrency=channel_limiter,
        registry=registry, oauth_manager=oauth, state_db=state, now=authority.clock,
    )
    media = MediaControl(media_db=MediaDbAuthority(authority), config=config)
    return ObservabilityControls(
        status=status, stats=stats, logs=Mock(), media=media, retention=Mock(),
    )


def _get(client, auth, path):
    response = client.get("/api/management/v1" + path, headers=auth)
    assert response.status_code == 200, response.text
    return response


def test_real_controls_asgi_authority_counts_health_revisions_and_read_only(tmp_path):
    artifact = tmp_path / "artifact.png"
    artifact.write_bytes(b"artifact")
    authority = Authority(artifact)
    controls = _real_controls(authority)
    client, _, _, auth = build_client(tmp_path, controls_value=controls)

    overview_first = _get(client, auth, "/overview").json()["data"]
    assert overview_first["counts"] == {
        "channels": 1, "oauthAccounts": 1, "apiKeys": 1, "quotaHot": 1,
    }
    assert controls.status.state_db.quota_keys == ["account-one"]

    runtime_first = _get(client, auth, "/runtime/status").json()["data"]
    api_channel = next(row for row in runtime_first["channels"] if row["id"] == "api:api-one")
    assert api_channel["health"] == "cooldown"
    assert api_channel["cooldownCount"] == 1
    assert api_channel["cooldowns"][0]["message"] == "authoritative cooldown reason"
    assert api_channel["problemReasons"] == ["authoritative cooldown reason"]
    assert runtime_first["problemChannels"][0]["id"] == "api:api-one"

    jobs = _get(client, auth, "/runtime/background-jobs").json()
    assert all(item["lastRunAt"] is None and item["nextRunAt"] is None for item in jobs["data"])
    assert {item["status"] for item in jobs["data"]} <= {"unknown", "disabled"}

    collection_paths = (
        "/runtime/background-jobs", "/runtime/cooldowns",
        "/stats/breakdown?dimension=channel", "/stats/recent-calls",
        "/media-logs",
    )
    collection_revisions = {}
    for path in collection_paths:
        payload = _get(client, auth, path).json()
        assert payload["meta"]["revision"].startswith("rev_")
        assert all(item["revision"].startswith("rev_") for item in payload["data"])
        collection_revisions[path] = payload["meta"]["revision"]
    for path, expected in collection_revisions.items():
        assert _get(client, auth, path).json()["meta"]["revision"] == expected

    artifacts = _get(client, auth, "/media-logs/1/artifacts").json()
    assert artifacts["meta"]["revision"].startswith("rev_")
    assert artifacts["data"][0]["revision"].startswith("rev_")

    single_paths = (
        "/runtime/concurrency", "/stats/summary",
        "/stats/models/model-one", "/preferences/telegram/stats",
        "/media-logs/1",
    )
    single_revisions = {}
    for path in single_paths:
        revision = _get(client, auth, path).json()["data"]["revision"]
        assert revision.startswith("rev_")
        single_revisions[path] = revision
    download = _get(client, auth, f"/media-logs/1/artifacts/{artifacts['data'][0]['id']}")
    assert download.content == b"artifact"

    # Clock-derived uptime/queue ages and hidden secret columns cannot churn a
    # public resource revision when the represented authority is unchanged.
    authority.clock.value += 7
    authority.oldest_wait_seconds += 7
    authority.config_data["apiKeys"]["client-one"] = "changed-downstream-secret"
    authority.channels[0].api_key = "changed-runtime-secret"
    authority.stats_hidden = "changed-stats-secret"
    authority.media_rows[0]["api_key"] = "changed-media-secret"

    overview_same = _get(client, auth, "/overview").json()["data"]
    runtime_same = _get(client, auth, "/runtime/status").json()["data"]
    concurrency_same = _get(client, auth, "/runtime/concurrency").json()["data"]
    stats_same = _get(client, auth, "/stats/summary").json()["data"]
    media_same = _get(client, auth, "/media-logs").json()
    assert overview_same["uptimeSeconds"] != overview_first["uptimeSeconds"]
    assert overview_same["revision"] == overview_first["revision"]
    assert runtime_same["revision"] == runtime_first["revision"]
    assert concurrency_same["revision"] == runtime_first["concurrency"]["revision"]
    assert stats_same["revision"] == single_revisions["/stats/summary"]
    assert media_same["meta"]["revision"] == collection_revisions["/media-logs"]

    serialized = json.dumps({
        "overview": overview_same, "runtime": runtime_same,
        "concurrency": concurrency_same, "stats": stats_same, "media": media_same,
        "artifacts": artifacts,
    })
    for secret in (
        "config-channel-secret", "changed-downstream-secret", "changed-runtime-secret",
        "oauth-runtime-secret", "quota-row-secret", "orphan-row-secret",
        "changed-stats-secret", "recent-call-secret", "changed-media-secret",
    ):
        assert secret not in serialized

    # Public resource changes do change their corresponding stable revisions.
    authority.config_data["apiKeys"]["client-two"] = "another-secret"
    assert _get(client, auth, "/overview").json()["data"]["revision"] != overview_first["revision"]
    authority.cooldown_rows[0]["last_error_message"] = "new authoritative reason"
    assert _get(client, auth, "/runtime/status").json()["data"]["revision"] != runtime_first["revision"]
    authority.stats_total += 1
    assert _get(client, auth, "/stats/summary").json()["data"]["revision"] != stats_same["revision"]
    authority.media_rows[0]["status"] = "failed"
    assert _get(client, auth, "/media-logs").json()["meta"]["revision"] != media_same["meta"]["revision"]

    assert authority.mutation_calls == []

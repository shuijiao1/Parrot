from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.management_api.schemas.observability import ConcurrencyData
from src.management_auth import AuthMethod, ManagementPrincipal
from src.management_control import ManagementContext
from src.management_control.observability import StatusControl
from src.management_control.observability import common as observability_common


def context():
    return ManagementContext(
        request_id="status-request",
        actor=ManagementPrincipal.administrator(
            subject_id="status-actor", auth_method=AuthMethod.MANAGEMENT_KEY,
        ),
    )


class Config:
    @staticmethod
    def get():
        return {
            "listen": {"host": "127.0.0.9", "port": 22129},
            "apiKeys": {"one": "write-only"}, "channels": [], "oauthAccounts": [],
            "affinity": {"cleanupIntervalSeconds": 345},
            "quotaMonitor": {"enabled": False, "intervalSeconds": 67},
            "cooldownRecovery": {"enabled": True, "intervalSeconds": 31},
        }


class Registry:
    @staticmethod
    def all_channels():
        return [SimpleNamespace(
            key="api:one", display_name="one", protocol="anthropic",
            type="api", enabled=True, disabled_reason=None,
        )]


class Cooldown:
    @staticmethod
    def active_entries():
        return [{
            "channel_key": "api:one", "model": "model", "error_count": 1,
            "cooldown_until": -1, "message": "failed",
        }]


class Scorer:
    @staticmethod
    def snapshot():
        return [{
            "channel_key": "api:one", "model": "model", "recent_requests": 2,
            "recent_success_count": 2, "score": 1, "avg_first_byte_ms": 10,
        }]


class Affinity:
    count = staticmethod(lambda: 1)
    client_count = staticmethod(lambda: 2)


class Limiter:
    totals = staticmethod(lambda: {"in_flight": 0, "waiting": 0, "tracked_channels": 1})
    snapshot = staticmethod(lambda: [{
        "channel_key": "api:one", "in_flight": 0, "max_concurrent": 2,
        "waiting": 0, "unlimited": False,
    }])


class ApiLimiter:
    totals = staticmethod(lambda: {"in_flight": 0, "waiting": 0, "tracked_keys": 1})
    snapshot = staticmethod(lambda: [{
        "key_name": "one", "enabled": True, "in_flight": 0,
        "max_concurrent": 2, "max_queue": 3, "queue_wait_seconds": 4,
        "waiting": 0, "oldest_wait_seconds": 0, "unlimited": False,
        "enabled_source": "key", "max_concurrent_source": "key",
        "max_queue_source": "key", "queue_wait_source": "key",
    }])


class Logs:
    @staticmethod
    def stats_summary(**kwargs):
        return {"overall": {"total": 1}}

    @staticmethod
    def stats_lifetime():
        return {"overall": {"total": 3}}

    @staticmethod
    def tps_by_channel_model(**kwargs):
        return {}


class OAuth:
    list_accounts = staticmethod(lambda: [])
    get_account_key = staticmethod(lambda account: "")
    provider_of = staticmethod(lambda account: "openai")


class State:
    quota_load_all = staticmethod(lambda: [])
    health = staticmethod(lambda: {"records": 1})


class StatusMonitor:
    snapshot_active = staticmethod(lambda: {})


class LoadBalancing:
    display_mode = staticmethod(lambda value: value)


class QuotaErrors:
    active_quota_cooldown = staticmethod(lambda row: False)
    format_bjt_ms = staticmethod(lambda value, compact: "never")


def test_status_control_readonly_snapshots_page_total_and_database_status():
    control = StatusControl(
        config=Config(), registry=Registry(), cooldown=Cooldown(), scorer=Scorer(),
        affinity=Affinity(), concurrency=Limiter(), apikey_limiter=ApiLimiter(),
        log_db=Logs(), oauth_manager=OAuth(), quota_errors=QuotaErrors(), state_db=State(),
        status_monitor=StatusMonitor(), load_balancing=LoadBalancing(),
        now=lambda: 1_700_000_000, service_started_at=1_699_999_900,
    )
    overview = control.overview(context())
    assert overview["uptimeSeconds"] == 100
    assert overview["listeners"] == {"host": "127.0.0.9", "port": 22129}
    assert overview["counts"] == {
        "channels": 1, "oauthAccounts": 0, "apiKeys": 1, "quotaHot": 0,
    }
    runtime = control.runtime_status(context())
    assert runtime["database"]["status"] == "healthy"
    assert runtime["cooldownSummary"] == {"active": 1, "permanent": 1}
    typed_concurrency = ConcurrencyData.model_validate(runtime["concurrency"])
    assert typed_concurrency.channelTotals.trackedChannels == 1
    assert typed_concurrency.channels[0].channelKey == "api:one"
    assert typed_concurrency.apiKeyTotals.trackedKeys == 1
    assert typed_concurrency.apiKeys[0].queueWaitSeconds == 4
    cooldowns = control.cooldown_page(context(), page=1, page_size=1)
    assert cooldowns.total == 1
    assert cooldowns.items[0]["state"] == "permanent"
    jobs = control.background_jobs(context(), page=1, page_size=20)
    assert jobs.total == 8 and not jobs.has_next
    by_id = {item["id"]: item for item in jobs.items}
    assert {item["status"] for item in jobs.items} <= {"unknown", "disabled"}
    assert by_id["walCheckpoint"]["intervalSeconds"] is None
    assert by_id["walCheckpoint"]["status"] == "unknown"
    assert by_id["affinityCleanup"]["intervalSeconds"] == 345
    assert by_id["quotaMonitor"] == {
        "id": "quotaMonitor", "intervalSeconds": 67,
        "lastRunAt": None, "nextRunAt": None, "status": "disabled", "error": None,
    }
    assert by_id["cooldownProbe"]["intervalSeconds"] == 31


def test_background_jobs_no_refresh_only_disables_token_rotation(monkeypatch):
    monkeypatch.setenv("PARROT_NO_REFRESH", "1")
    control = StatusControl(config=Config(), oauth_manager=OAuth())
    jobs = {item["id"]: item for item in control.background_jobs(
        context(), page=1, page_size=20,
    ).items}
    assert jobs["oauthRefresh"]["status"] == "disabled"
    assert jobs["quotaMonitor"]["status"] == "disabled"  # Config().quotaMonitor.enabled is false.
    for job_id in ("oauthModelSync", "providerUsage"):
        assert jobs[job_id]["status"] == "unknown"


def test_common_require_only_maps_real_capability_denials(monkeypatch):
    def programming_error(_actor, _capability):
        raise RuntimeError("policy implementation failed")

    monkeypatch.setattr(observability_common, "authorize", programming_error)
    with pytest.raises(RuntimeError, match="policy implementation failed"):
        observability_common.require(context())


@pytest.mark.parametrize("cooldown_until", [1_700_000_600_000, -1])
def test_runtime_fastest_excludes_temporary_and_permanent_cooldown_pairs(cooldown_until):
    class PairCooldown:
        @staticmethod
        def active_entries():
            return [{
                "channel_key": "api:one", "model": "cooled-model",
                "error_count": 1, "cooldown_until": cooldown_until,
            }]

    class PairScorer:
        @staticmethod
        def snapshot():
            return [
                {
                    "channel_key": "api:one", "model": "cooled-model",
                    "recent_requests": 2, "recent_success_count": 2,
                    "score": 1, "avg_first_byte_ms": 10,
                },
                {
                    "channel_key": "api:one", "model": "available-model",
                    "recent_requests": 2, "recent_success_count": 2,
                    "score": 2, "avg_first_byte_ms": 20,
                },
            ]

    control = StatusControl(
        config=Config(), registry=Registry(), cooldown=PairCooldown(), scorer=PairScorer(),
        affinity=Affinity(), concurrency=Limiter(), apikey_limiter=ApiLimiter(),
        log_db=Logs(), oauth_manager=OAuth(), quota_errors=QuotaErrors(), state_db=State(),
        status_monitor=StatusMonitor(), load_balancing=LoadBalancing(),
    )

    fastest = control.runtime_status(context())["fastestByFamily"]["anthropic"]

    assert [item["model"] for item in fastest] == ["available-model"]


def test_runtime_error_and_message_fields_preserve_business_text():
    disabled_reason = "Bearer provider routing is unavailable"
    cooldown_message = "Basic tier is temporarily unavailable"
    alert_message = "Bearer support is enabled"

    class SecretRegistry:
        @staticmethod
        def all_channels():
            return [SimpleNamespace(
                key="api:one", display_name="one", protocol="anthropic",
                type="api", enabled=False,
                disabled_reason=disabled_reason,
            )]

    class SecretCooldown:
        @staticmethod
        def active_entries():
            return [{
                "channel_key": "api:one", "model": "model", "error_count": 1,
                "cooldown_until": -1,
                "message": cooldown_message,
            }]

    class SecretStatusMonitor:
        snapshot_active = staticmethod(lambda: {"error": alert_message})

    control = StatusControl(
        config=Config(), registry=SecretRegistry(), cooldown=SecretCooldown(), scorer=Scorer(),
        affinity=Affinity(), concurrency=Limiter(), apikey_limiter=ApiLimiter(),
        log_db=Logs(), oauth_manager=OAuth(), quota_errors=QuotaErrors(), state_db=State(),
        status_monitor=SecretStatusMonitor(), load_balancing=LoadBalancing(),
        now=lambda: 1_700_000_000, service_started_at=1_699_999_900,
    )

    exposed = {
        "overview": control.overview(context()),
        "runtime": control.runtime_status(context()),
        "cooldowns": list(control.cooldown_page(context(), page=1, page_size=10).items),
    }
    serialized = json.dumps(exposed, default=str)

    assert disabled_reason in serialized
    assert cooldown_message in serialized
    assert alert_message in serialized

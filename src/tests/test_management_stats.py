from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.management_auth import AuthMethod, ManagementPrincipal
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode
from src.management_control.observability import (
    StatsBreakdownQuery, StatsControl, StatsDimension, StatsPeriod, StatsSort,
)
from src.management_api.schemas.observability import ModelStatsChannelData, StatsMetricData
from src.tests.management_observability_support import build_client


def _context(*, write=True):
    capabilities = [] if not write else None
    principal = (
        ManagementPrincipal.administrator(subject_id="stats-actor", auth_method=AuthMethod.MANAGEMENT_KEY)
        if capabilities is None else
        ManagementPrincipal.with_capabilities(
            subject_id="stats-actor", auth_method=AuthMethod.MANAGEMENT_KEY,
            capabilities=capabilities, issued_at=datetime.now(timezone.utc),
        )
    )
    return ManagementContext(request_id="stats-request", actor=principal)


class FakeConfig:
    def __init__(self):
        self.value = {"telegram": {}, "concurrency": {"enabled": True}}
        self.updates = 0

    def get(self):
        return self.value

    def update(self, mutate):
        self.updates += 1
        mutate(self.value)
        return self.value


class FakeLogDb:
    def stats_period_snapshot(self, since):
        return {
            "summary": {
                "overall": {"total": 3, "success_count": 2},
                "by_model": [
                    {"key": "small", "metrics": {"total": 1, "cost_ticks": 10}},
                    {"key": "large", "metrics": {"total": 2, "cost_ticks": 30}},
                ],
            },
            "families": {"anthropic": {"overall": {"total": 3}}},
            "by_channel": {"api:b": {"total": 2}, "api:a": {"total": 1}},
            "by_apikey": {"key": {"total": 3}},
        }

    def stats_lifetime(self):
        return {"overall": {"total": 100}}

    def channels_by_requested_model(self, since):
        return {"large": [{"key": "api:b", "count": 2}]}

    def recent_logs_count(self):
        return 1

    def recent_logs(self, limit, offset=0):
        return [{"request_id": "r", "status": "success"}][offset:offset + limit]

    def request_totals_by_apikey(self):
        return {"key": 3}


class EmptyRuntime:
    @staticmethod
    def totals():
        return {"in_flight": 0, "waiting": 0, "tracked_channels": 0}


class EmptyRegistry:
    @staticmethod
    def get_channel(_key):
        return None


def test_stats_api_happy_control_once_validation_and_patch_schema(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    cases = [
        ("GET", "/api/management/v1/stats/summary?period=today", None, controls.stats.summary),
        ("GET", "/api/management/v1/stats/breakdown?dimension=channel&pageSize=10", None, controls.stats.breakdown),
        ("GET", "/api/management/v1/stats/models/example-model", None, controls.stats.model_stats),
        ("GET", "/api/management/v1/stats/recent-calls", None, controls.stats.recent_calls),
        ("GET", "/api/management/v1/preferences/telegram/stats", None, controls.stats.get_preferences),
        ("PATCH", "/api/management/v1/preferences/telegram/stats", {"byChannel": False}, controls.stats.update_preferences),
    ]
    for method, path, body, mocked in cases:
        response = client.request(method, path, json=body, headers=auth)
        assert response.status_code == 200, response.text
        assert response.json()["meta"]["requestId"] == "request-p4-test"
        mocked.assert_called_once()
        assert mocked.call_args.args[0].actor.subject_id == "administrator"

    invalid = client.get("/api/management/v1/stats/summary?period=never", headers=auth)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["fields"][0]["path"] == "period"
    extra = client.patch(
        "/api/management/v1/preferences/telegram/stats",
        json={"unknown": True}, headers=auth,
    )
    assert extra.status_code == 422
    assert extra.json()["error"]["fields"][0]["path"] == "unknown"


def test_stats_control_summary_breakdown_model_page_total_and_preferences_revision():
    config = FakeConfig()
    control = StatsControl(
        log_db=FakeLogDb(), config=config, concurrency=EmptyRuntime(), registry=EmptyRegistry(),
        now=lambda: 1_700_000_000,
    )
    context = _context()
    summary = control.summary(context, StatsPeriod.TODAY)
    assert summary["overall"]["total"] == 3
    assert summary["families"]["anthropic"]["total"] == 3

    result = control.breakdown(context, StatsBreakdownQuery(
        dimension=StatsDimension.MODEL, period=StatsPeriod.SEVEN_DAYS,
        sort=StatsSort.COST, page=1, page_size=1,
    ))
    assert result.total == 2 and result.has_next
    assert result.items[0]["key"] == "large"
    model = control.model_stats(context, "large", StatsPeriod.MONTH)
    assert model["channels"][0]["key"] == "api:b"
    with pytest.raises(ManagementError) as missing:
        control.model_stats(context, "missing", StatsPeriod.MONTH)
    assert missing.value.code is ManagementErrorCode.RESOURCE_NOT_FOUND

    initial = control.get_preferences(context)
    changed = control.update_preferences(
        context, {"byChannel": False}, expected_revision=initial["revision"],
    )
    assert changed["byChannel"] is False and config.updates == 1
    with pytest.raises(ManagementError) as stale:
        control.update_preferences(context, {"byModel": False}, expected_revision=initial["revision"])
    assert stale.value.code is ManagementErrorCode.REVISION_CONFLICT


def test_stats_real_channel_apikey_shapes_preserve_tokens_cache_cost_latency_and_token_sort():
    class RealShapeLogDb(FakeLogDb):
        def stats_period_snapshot(self, since):
            return {
                "summary": {
                    "overall": {
                        "total": 4, "success_count": 3,
                        "total_input_tokens": 17, "total_output_tokens": 9,
                        "total_cache_creation": 6, "total_cache_read": 8,
                        "cost_ticks": 90, "avg_total_ms": 125, "avg_tps": 12.5,
                    },
                    "by_model": [{
                        "key": "model-real",
                        "metrics": {
                            "total": 4, "total_prompt_tokens": 31,
                            "total_output_tokens": 9, "total_cache_creation": 6,
                            "total_cache_read": 8, "avg_connect_ms": 5,
                            "avg_first_token_ms": 20, "cost_ticks": 90,
                            "avg_tps": 12.5,
                        },
                    }],
                },
                "families": {"anthropic": {"overall": {
                    "total": 4, "total_input_tokens": 17,
                    "total_output_tokens": 9, "total_cache_creation": 6,
                    "total_cache_read": 8,
                }}},
                "by_channel": {
                    "api:plain": {
                        "total": 2, "input": 10, "output": 10,
                        "cache_creation": 1, "cache_read": 1,
                        "cost_ticks": 30, "avg_tps": 10,
                    },
                    "api:cached": {
                        "total": 2, "input": 1, "output": 1,
                        "cache_creation": 50, "cache_read": 40,
                        "cost_ticks": 60, "avg_tps": 15,
                    },
                },
                "by_apikey": {
                    "plain-key": {"total": 2, "input": 8, "output": 8},
                    "cached-key": {
                        "total": 2, "input": 1, "output": 1,
                        "cache_creation": 30, "cache_read": 20,
                    },
                },
            }

        def channels_by_requested_model(self, since):
            return {"model-real": [{
                "key": "api:cached", "count": 3, "type": "api",
                "upstream_protocol": "anthropic",
            }]}

    control = StatsControl(
        log_db=RealShapeLogDb(), config=FakeConfig(), concurrency=EmptyRuntime(),
        registry=EmptyRegistry(), now=lambda: 1_700_000_000,
    )
    ctx = _context()
    summary = control.summary(ctx, StatsPeriod.TODAY)
    assert summary["overall"] == {
        **summary["overall"],
        "inputTokens": 17, "outputTokens": 9,
        "cacheCreationTokens": 6, "cacheReadTokens": 8,
        "costTicks": 90, "averageTotalMilliseconds": 125.0,
        "averageTokensPerSecond": 12.5,
    }
    for dimension, expected in (
        (StatsDimension.CHANNEL, "api:cached"),
        (StatsDimension.API_KEY, "cached-key"),
    ):
        result = control.breakdown(ctx, StatsBreakdownQuery(
            dimension=dimension, period=StatsPeriod.TODAY,
            sort=StatsSort.TOKENS, page=1, page_size=10,
        ))
        assert result.items[0]["key"] == expected
        metrics = result.items[0]["metrics"]
        assert metrics["cacheCreationTokens"] > 0
        assert metrics["cacheReadTokens"] > 0

    model = control.model_stats(ctx, "model-real", StatsPeriod.TODAY)
    assert model["metrics"]["inputTokens"] == 17
    assert model["metrics"]["cacheCreationTokens"] == 6
    assert model["metrics"]["averageFirstTokenMilliseconds"] == 20.0
    assert model["channels"] == [{
        "key": "api:cached", "count": 3, "type": "api",
        "upstreamProtocol": "anthropic",
    }]

    StatsMetricData.model_validate(model["metrics"])
    ModelStatsChannelData.model_validate(model["channels"][0])
    with pytest.raises(ValidationError):
        StatsMetricData.model_validate({**model["metrics"], "unknownMetric": 1})
    with pytest.raises(ValidationError):
        ModelStatsChannelData.model_validate({**model["channels"][0], "secret": "x"})

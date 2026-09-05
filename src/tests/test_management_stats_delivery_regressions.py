"""Real server/DB regression gates for channel cost and grouped counters."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from src import config, log_db
from src.tests.test_management_delivery_regressions import actual_management, PREFIX


@pytest.fixture
def stats_app(actual_management, tmp_path, monkeypatch):
    client, _runtime = actual_management
    log_root = tmp_path / "stats-logs"
    log_root.mkdir()
    monkeypatch.setattr(log_db, "_log_dir", str(log_root))
    monkeypatch.setattr(log_db, "_local", threading.local())
    yield client


def _data(client, path, **params):
    response = client.get(PREFIX + path, params=params)
    assert response.status_code == 200, response.text
    return response.json()["data"]


@pytest.mark.parametrize("ticks,expected", [
    (2_500_000_000, "0.25"), (0, "0"), (1, "0.0000000001"), (None, None),
])
def test_channel_month_cost_preserves_known_zero_and_unknown(stats_app, ticks, expected):
    client = stats_app
    model = "grok-4.5" if ticks is not None else "audit-unpriced-channel-model"
    bindings = {model: {"target": "xai/grok-4.5", "source": "manual"}} if ticks is not None else {}
    config.update(lambda current: current.update({
        "logStoreBodies": True, "modelBindings": {"defaults": bindings, "scoped": {}},
    }))
    created = client.post(PREFIX + "/channels", json={
        "mode": "manual", "name": "cost-regression", "baseUrl": "https://example.test",
        "apiKey": "regression-only-not-real-key", "protocol": "openai-responses",
        "models": [{"real": model, "alias": model}],
    })
    assert created.status_code == 201, created.text
    channel_id = created.json()["data"]["id"]
    handle = log_db.insert_pending("channel-cost", "127.0.0.1", "stats-key", model, False, 1, 0, {}, {})
    attempt = log_db.record_retry_attempt(handle, 1, channel_id, "api", model, time.time(), upstream_protocol="openai-responses")
    log_db.mark_retry_attempt_dispatch(attempt, {"model": model})
    usage = {"input_tokens": 10, "output_tokens": 3}
    if ticks is not None:
        usage["cost_in_usd_ticks"] = ticks
    log_db.finish_success(handle, channel_id, "api", model, input_tokens=10, output_tokens=3,
                          response_body=json.dumps({"usage": usage}), upstream_protocol="openai-responses")
    backend = log_db.tokens_for_channel(channel_id, 0)
    assert backend["cost_ticks"] == (ticks or 0)
    assert backend["costed_success"] == (0 if ticks is None else 1)
    detail = _data(client, "/channels/" + quote(channel_id, safe=""))
    assert detail["monthStats"]["cost"] == expected
    assert detail["monthStats"]["total"] == 1
    assert detail["monthStats"]["inputTokens"] == 10
    assert detail["modelStats"][0]["costTicks"] == (ticks or 0)


_COUNTERS = ("total", "successCount", "errorCount", "pendingCount", "totalRetries", "retriedRequests", "affinityHits")


def _metrics(*values):
    return dict(zip(_COUNTERS, values))


def _counts(metrics):
    return {key: metrics[key] for key in _COUNTERS}


def _pending(identifier, key="key-a", model="provider/model-a", created_at=None):
    return log_db.insert_pending(identifier, "127.0.0.1", key, model, False, 1, 0, {}, {}, created_at=created_at)


@pytest.mark.parametrize("period", ["today", "lifetime"])
def test_grouped_counters_keep_dimensions_periods_and_pending_without_channel(stats_app, period):
    client = stats_app
    first = _pending("counter-success")
    log_db.finish_success(first, "api:channel-a", "api", "provider/model-a", retry_count=2,
                          affinity_hit=1, upstream_protocol="openai-responses")
    failed = _pending("counter-error")
    log_db.finish_error(failed, "regression-only-error", retry_count=1, final_channel_key="api:channel-a",
                        final_channel_type="api", final_model="provider/model-a", upstream_protocol="openai-responses")
    _pending("counter-pending")
    other = _pending("counter-other", "key-b", "provider/model-b")
    log_db.finish_success(other, "api:channel-b", "api", "provider/model-b", upstream_protocol="openai-responses")
    now = datetime.now(timezone(timedelta(hours=8)))
    previous_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    historical = _pending("counter-historical", created_at=previous_month.timestamp())
    log_db.finish_success(historical, "api:channel-a", "api", "provider/model-a", retry_count=3,
                          affinity_hit=1, upstream_protocol="openai-responses")
    extra = int(period == "lifetime")
    a = _metrics(3 + extra, 1 + extra, 1, 1, 3 + extra * 3, 2 + extra, 1 + extra)
    channel_a = _metrics(2 + extra, 1 + extra, 1, 0, 3 + extra * 3, 2 + extra, 1 + extra)
    b = _metrics(1, 1, 0, 0, 0, 0, 0)
    pending = _metrics(1, 0, 0, 1, 0, 0, 0)
    expected = {
        "channel": {"api:channel-a": channel_a, "api:channel-b": b, "?": pending},
        "model": {"provider/model-a": a, "provider/model-b": b},
        "apiKey": {"key-a": a, "key-b": b},
    }
    summary = _data(client, "/stats/summary", period=period)["overall"]
    assert _counts(summary) == _metrics(4 + extra, 2 + extra, 1, 1, 3 + extra * 3, 2 + extra, 1 + extra)
    for dimension, expected_rows in expected.items():
        rows = _data(client, "/stats/breakdown", period=period, dimension=dimension)
        assert {row["key"]: _counts(row["metrics"]) for row in rows} == expected_rows
    detail = _data(client, "/stats/models/" + quote("provider/model-a", safe=""), period=period)
    assert _counts(detail["metrics"]) == a
    # Both SQL paths feed the same accumulator; family snapshots must keep the
    # new counters too, without changing existing token/cost/TPS projection.
    since = 0 if extra else now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    raw = log_db.stats_summary(since, include_family_slices=True)
    family_a = next(row["metrics"] for row in raw["family_results"]["openai"]["by_model"] if row["key"] == "provider/model-a")
    assert [family_a[key] for key in ("pending_count", "total_retries", "retried_requests", "affinity_hits")] == [0, 3 + extra * 3, 2 + extra, 1 + extra]


def test_empty_statistics_retain_zero_counts_and_missing_model(stats_app):
    summary = _data(stats_app, "/stats/summary")["overall"]
    assert _counts(summary) == _metrics(0, 0, 0, 0, 0, 0, 0)
    for dimension in ("channel", "model", "apiKey"):
        assert _data(stats_app, "/stats/breakdown", dimension=dimension) == []
    assert stats_app.get(PREFIX + "/stats/models/missing").status_code == 404

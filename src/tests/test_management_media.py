from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from src.management_auth import AuthMethod, ManagementPrincipal
from src.management_control import ManagementContext, ManagementError, ManagementErrorCode
from src.management_control.observability import MediaAction, MediaControl, MediaLogQuery, MediaSort, MediaStatus
from src.tests.management_observability_support import build_client


def context():
    return ManagementContext(
        request_id="media-request",
        actor=ManagementPrincipal.administrator(
            subject_id="media-actor", auth_method=AuthMethod.MANAGEMENT_KEY,
        ),
    )


class FakeConfig:
    def get(self):
        return {"oauthAccounts": [{"provider": "openai", "email": "a@example.test"}]}


class FakeMediaDb:
    def __init__(self, rows):
        self.rows = rows

    def count(self):
        return len(self.rows)

    def recent(self, limit, offset=0):
        return self.rows[offset:offset + limit]

    def summary(self):
        return {"total": len(self.rows)}

    def account_top(self, limit):
        return []

    def get_log(self, log_id):
        return next((row for row in self.rows if row["id"] == log_id), None)

    def fmt_bjt(self, value):
        return str(value)

    def seconds_since(self, value):
        return 1


def _row(identifier, status, action, created, path):
    return {
        "id": identifier, "request_id": f"request-{identifier}", "status": status,
        "provider": "openai", "model": "gpt-image", "action": action,
        "media_type": "image", "progress": 100, "aspect_ratio": "1:1",
        "resolution": "1024x1024", "duration_ms": identifier * 10,
        "cost_usd_ticks": identifier, "image_bytes": 3, "created_at": created,
        "finished_at": created + 1, "cache_paths": json.dumps([str(path)]),
        "http_status": 200, "prompt_preview": "safe",
    }


def test_media_api_happy_download_control_once_validation_and_missing(tmp_path):
    client, _, controls, auth = build_client(tmp_path)
    cases = [
        ("/api/management/v1/media-logs?status=success", controls.media.list_logs),
        ("/api/management/v1/media-logs/1", controls.media.detail),
        ("/api/management/v1/media-logs/1/artifacts", controls.media.artifacts),
        ("/api/management/v1/media-logs/1/artifacts/artifact_1_example", controls.media.download),
    ]
    artifact = None
    for path, mocked in cases:
        response = client.get(path, headers=auth)
        assert response.status_code == 200, response.text
        mocked.assert_called_once()
        assert mocked.call_args.args[0].actor.subject_id == "administrator"
        if mocked is controls.media.download:
            artifact = response
    assert artifact is not None
    assert artifact.content == b"png"
    assert artifact.headers["content-type"] == "image/png"

    bad = client.get("/api/management/v1/media-logs?status=unknown", headers=auth)
    assert bad.status_code == 422
    assert bad.json()["error"]["fields"][0]["path"] == "status[0]"
    controls.media.detail.side_effect = ManagementError(ManagementErrorCode.RESOURCE_NOT_FOUND)
    missing = client.get("/api/management/v1/media-logs/404", headers=auth)
    assert missing.status_code == 404


def test_media_control_filter_sort_page_artifacts_download_and_expiry(tmp_path):
    first = tmp_path / "first.png"
    first.write_bytes(b"png")
    rows = [
        _row(1, "success", "generate", 100, first),
        _row(2, "failed", "edit", 200, tmp_path / "missing.png"),
        _row(3, "success", "extend", 300, first),
    ]
    control = MediaControl(media_db=FakeMediaDb(rows), config=FakeConfig())
    result = control.list_logs(context(), MediaLogQuery(
        statuses=(MediaStatus.SUCCESS,), actions=(MediaAction.GENERATE, MediaAction.EXTEND),
        sort=MediaSort.CREATED_AT, page=1, page_size=1,
    ))
    assert result.total == 2 and result.has_next
    assert result.items[0]["id"] == "3"

    detail = control.detail(context(), "1")
    assert detail["artifactCount"] == 1 and detail["paths"] == ["first.png"]
    artifacts = control.artifacts(context(), "1")
    assert artifacts[0]["contentType"] == "image/png"
    download = control.download(context(), "1", artifacts[0]["id"])
    assert b"".join(download.chunks) == b"png"
    with pytest.raises(ManagementError) as expired:
        control.download(context(), "2", "artifact_1_missing")
    assert expired.value.code is ManagementErrorCode.RESOURCE_NOT_FOUND


def test_media_nondefault_scan_is_chunk_bounded_with_exact_sort_page_and_total(tmp_path):
    class TrackingMediaDb(FakeMediaDb):
        def __init__(self, rows):
            super().__init__(rows)
            self.limits = []

        def recent(self, limit, offset=0):
            self.limits.append(limit)
            return super().recent(limit, offset=offset)

    path = tmp_path / "unused.png"
    rows = [
        _row(
            identifier, "success" if identifier % 4 else "failed",
            "generate" if identifier % 3 else "edit", identifier, path,
        )
        for identifier in range(1001, 0, -1)
    ]
    db = TrackingMediaDb(rows)
    control = MediaControl(media_db=db, config=FakeConfig())
    query = MediaLogQuery(
        statuses=(MediaStatus.SUCCESS,), actions=(MediaAction.GENERATE,),
        sort=MediaSort.COST, descending=False, page=3, page_size=11,
    )
    result = control.list_logs(context(), query)
    expected = [
        row for row in rows
        if row["status"] == "success" and row["action"] == "generate"
    ]
    expected.sort(key=lambda row: row["cost_usd_ticks"])
    assert result.total == len(expected)
    assert [item["id"] for item in result.items] == [
        str(row["id"]) for row in expected[22:33]
    ]
    assert len(db.limits) == 6
    assert max(db.limits) <= 200

    db.limits.clear()
    default = control.list_logs(context(), MediaLogQuery(page=2, page_size=13))
    assert default.total == 1001
    assert db.limits == [13]
    assert [item["id"] for item in default.items] == [
        str(row["id"]) for row in rows[13:26]
    ]


def test_media_control_time_bounds_reject_naive_and_reverse_without_type_error(tmp_path):
    row = _row(1, "success", "generate", 100, tmp_path / "missing.png")
    control = MediaControl(media_db=FakeMediaDb([row]), config=FakeConfig())
    for query, path in (
        (MediaLogQuery(started_at=datetime(2026, 1, 2, 3, 4, 5)), "startedAt"),
        (MediaLogQuery(
            started_at=datetime(2026, 1, 3, tzinfo=timezone.utc),
            ended_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        ), "endedAt"),
    ):
        with pytest.raises(ManagementError) as invalid:
            control.list_logs(context(), query)
        assert invalid.value.code is ManagementErrorCode.VALIDATION_FAILED
        assert invalid.value.fields[0].path == path


def test_expired_media_record_blocks_metadata_and_download_but_success_expiry_does_not(
    tmp_path,
):
    marker = tmp_path / "artifact.png"
    marker.write_bytes(b"artifact")
    expired = _row(1, "expired", "generate", 100, marker)
    successful = _row(2, "success", "generate", 200, marker)
    # This is a residual job-binding expiry, not an artifact expiry signal.
    successful["expires_at"] = 1
    control = MediaControl(
        media_db=FakeMediaDb([expired, successful]), config=FakeConfig(),
    )

    for access in (
        lambda: control.artifacts(context(), "1"),
        lambda: control.download(context(), "1", control._artifact_id(1, str(marker))),
    ):
        with pytest.raises(ManagementError) as missing:
            access()
        assert missing.value.code is ManagementErrorCode.RESOURCE_NOT_FOUND

    metadata = control.artifacts(context(), "2")
    assert metadata[0]["expiresAt"] == datetime.fromtimestamp(1, tz=timezone.utc)
    assert b"".join(control.download(context(), "2", metadata[0]["id"]).chunks) == b"artifact"


def test_expired_media_artifact_http_is_stable_404(tmp_path):
    marker = tmp_path / "artifact.png"
    marker.write_bytes(b"artifact")
    control = MediaControl(
        media_db=FakeMediaDb([_row(1, "expired", "generate", 100, marker)]),
        config=FakeConfig(),
    )
    client, _, controls, auth = build_client(tmp_path)
    controls.media = control

    metadata = client.get(
        "/api/management/v1/media-logs/1/artifacts", headers=auth,
    )
    download = client.get(
        f"/api/management/v1/media-logs/1/artifacts/{control._artifact_id(1, str(marker))}",
        headers=auth,
    )

    for response in (metadata, download):
        assert response.status_code == 404, response.text
        assert response.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_media_error_text_is_sanitized_without_changing_business_text(tmp_path):
    marker = "P4_SECRET_MARKER"
    row = _row(1, "failed", "generate", 100, tmp_path / "missing.png")
    row["error_message"] = f"github_token={marker}; ordinary provider failure"
    control = MediaControl(media_db=FakeMediaDb([row]), config=FakeConfig())

    result = control.list_logs(context(), MediaLogQuery())

    assert marker not in result.items[0]["error"]
    assert "ordinary provider failure" in result.items[0]["error"]


def test_media_detail_direct_and_http_sanitize_raw_text_without_mutating_tg_row(tmp_path):
    marker = "P4_MEDIA_DETAIL_MARKER"
    aliases = (
        "apiToken", "api_key", "x-api-key", "accessToken", "refresh_token",
        "id-token", "managementKey", "management_token", "botToken", "bot_key",
        "githubToken", "github_key", "clientSecret", "exchange_secret",
        "challengeSecret", "sessionSecret", "sessionToken", "password", "passwd",
        "cookie", "set-cookie", "credential",
    )
    alias_text = "; ".join(
        f"{key}={marker}_alias_{index}" for index, key in enumerate(aliases)
    )
    escaped_fragment = rf'prefix {{\"apiToken\":\"{marker}_escaped\"}} suffix'
    json_fragment = f'prefix {{"api_token":"{marker}_json"}} suffix'
    nested_json = json.dumps({
        "payload": json.dumps({"sessionToken": f"{marker}_nested"}),
    })
    prompt_preview = " | ".join((
        "ordinary prompt remains",
        f"session={marker}_session_equals",
        f"session: {marker}_session_colon",
        f"Authorization: Bearer {marker}_authorization",
        f"Proxy-Authorization: Basic {marker}_proxy_authorization",
        f"upstream said Bearer {marker}_bearer failed",
        f"Basic {marker}_basic rejected",
        f"socks5://{marker}_user:password@proxy.example:1080/path",
        f"https://{marker}_username@example.test/media/path",
        alias_text,
        json_fragment,
        escaped_fragment,
        nested_json,
    ))
    artifact = tmp_path / f"passwd={marker}_path; ordinary-image.png"
    artifact.write_bytes(b"png")
    row = _row(1, "success", "generate", 100, artifact)
    row.update({
        "error_message": (
            f"ordinary provider failure; upstream said Bearer {marker}_error failed"
        ),
        "account_key": f"ordinary account id; session={marker}_account",
        "account_email": f"ordinary account label; {escaped_fragment}",
        "upstream_request_id": (
            f"ordinary upstream request; custom://{marker}_user@request.example/id"
        ),
        "upstream_status": f"ordinary upstream status; Basic {marker}_status rejected",
        "prompt_preview": prompt_preview,
    })
    raw_row = dict(row)
    db = FakeMediaDb([row])
    control = MediaControl(media_db=db, config=FakeConfig())

    direct = control.detail(context(), "1")
    client, runtime, controls, auth = build_client(tmp_path)
    controls.media = control
    response = client.get("/api/management/v1/media-logs/1", headers=auth)
    openapi = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    assert openapi.status_code == 200, openapi.text

    for detail in (direct, response.json()["data"]):
        assert marker not in json.dumps(detail, default=str)
        assert "ordinary provider failure" in detail["error"]
        assert "ordinary account id" in detail["accountId"]
        assert "ordinary account label" in detail["accountLabel"]
        assert "ordinary upstream request" in detail["upstreamRequestId"]
        assert "ordinary upstream status" in detail["upstreamStatus"]
        assert "ordinary prompt remains" in detail["promptPreview"]
        assert "upstream said Bearer <redacted> failed" in detail["promptPreview"]
        assert "socks5://proxy.example:1080/path" in detail["promptPreview"]
        assert "https://example.test/media/path" in detail["promptPreview"]
        assert r'{\"apiToken\":\"<redacted>\"}' in detail["promptPreview"]
        assert detail["artifactCount"] == 1
        assert detail["paths"] == ["passwd=<redacted>; ordinary-image.png"]

    assert marker not in response.text
    assert marker not in json.dumps(runtime.state_store.audit_snapshot(), default=str)
    assert not runtime.operations._items
    assert marker not in openapi.text

    assert db.rows[0] == raw_row
    telegram_raw = control.raw_log_for_telegram(context(), 1)
    assert telegram_raw == raw_row
    assert telegram_raw is not db.rows[0]
    assert marker in json.dumps(telegram_raw, default=str)
    assert telegram_raw["prompt_preview"] == prompt_preview

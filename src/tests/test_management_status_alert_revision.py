from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any

from fastapi.testclient import TestClient

from src.management_api.routers.auxiliary_support import get_bound_auxiliary_controls
from src.management_control.auxiliary.status_alerts import StatusAlertControl
from src.tests.management_auxiliary_support import (
    bearer,
    build_auxiliary_app,
    create_session,
)


BASE = "/api/management/v1"


class FakeIncidentFeedAndMuteStore:
    """Isolated StatusGateway fake with separate remote feed and local mute state."""

    def __init__(self) -> None:
        self.active = {
            "claude": [
                {
                    "id": "inc-active",
                    "name": "Active incident",
                    "impact": "major",
                    "status": "investigating",
                    "created_at": "2026-01-02T03:00:00Z",
                    "updated_at": "2026-01-02T03:05:00Z",
                    "shortlink": "https://status.example/inc-active",
                }
            ],
            "openai": [],
            "cloudflare": [],
        }
        self.recent = {
            "claude": [
                copy.deepcopy(self.active["claude"][0]),
                {
                    "id": "inc-resolved",
                    "name": "Resolved incident",
                    "impact": "minor",
                    "status": "resolved",
                    "created_at": "2026-01-01T01:00:00Z",
                    "updated_at": "2026-01-01T02:00:00Z",
                    "shortlink": "https://status.example/inc-resolved",
                },
                {
                    "id": "inc-muted",
                    "name": "Already muted incident",
                    "impact": "critical",
                    "status": "monitoring",
                    "created_at": "2025-12-31T01:00:00Z",
                    "updated_at": "2025-12-31T02:00:00Z",
                    "shortlink": "https://status.example/inc-muted",
                },
            ],
            "openai": [],
            "cloudflare": [],
        }
        self.muted: dict[tuple[str, str], dict[str, Any]] = {
            ("claude", "inc-muted"): {
                "provider": "claude",
                "incident_id": "inc-muted",
                "name": "Already muted incident",
                "muted_at": 900,
            }
        }
        self.mute_calls: list[tuple[str, str, str]] = []
        self.unmute_calls: list[tuple[str, str]] = []
        self._timestamp = 1000

    def snapshot_active(self):
        return copy.deepcopy(self.active)

    def list_muted(self):
        return copy.deepcopy(list(self.muted.values()))

    def forget_provider(self, provider):
        self.active[provider] = []

    def refresh_provider(self, provider):
        return None

    def list_recent(self, provider, limit):
        return copy.deepcopy(self.recent.get(provider, []))[:limit]

    def mute(self, provider, incident_id, name=""):
        self.mute_calls.append((provider, incident_id, name))
        self._timestamp += 1
        self.muted[(provider, incident_id)] = {
            "provider": provider,
            "incident_id": incident_id,
            "name": name,
            "muted_at": self._timestamp,
        }
        self.active[provider] = [
            row for row in self.active.get(provider, []) if row.get("id") != incident_id
        ]

    def unmute(self, provider, incident_id):
        self.unmute_calls.append((provider, incident_id))
        self.muted.pop((provider, incident_id), None)

    def provider_tag(self, provider):
        return provider

    def provider_label(self, provider):
        return provider.title()

    def impact_icon(self, impact):
        return "!"

    def status_icon(self, status):
        return "?"


def _build_status_app(tmp_path):
    app, _, fixture = build_auxiliary_app(tmp_path)
    gateway = FakeIncidentFeedAndMuteStore()
    control = StatusAlertControl(
        config_gateway=fixture.config,
        status_gateway=gateway,
        audit_sink=fixture.audit,
    )
    controls = replace(fixture.controls, status_alerts=control)
    app.dependency_overrides[get_bound_auxiliary_controls] = lambda: controls
    return app, gateway


def _item(response, incident_id: str) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    return next(item for item in response.json()["data"]["items"] if item["id"] == incident_id)


def test_revisions_from_active_history_and_muted_views_drive_mute_and_unmute(tmp_path):
    app, gateway = _build_status_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))

        active = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "active", "provider": "claude"},
                headers=headers,
            ),
            "inc-active",
        )
        history = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "history", "provider": "claude"},
                headers=headers,
            ),
            "inc-active",
        )
        assert active["active"] is True
        assert history["active"] is False
        assert active["revision"] == history["revision"]

        already_muted_history = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "history", "provider": "claude"},
                headers=headers,
            ),
            "inc-muted",
        )
        already_muted_list = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "muted", "provider": "claude"},
                headers=headers,
            ),
            "inc-muted",
        )
        assert already_muted_history["muted"] is True
        assert already_muted_history["mutedAt"] == "1970-01-01T00:15:00Z"
        assert already_muted_history["revision"] == already_muted_list["revision"]

        muted = client.post(
            BASE + "/status-alerts/incidents/inc-active/actions/mute",
            headers={**headers, "If-Match": active["revision"]},
        )
        assert muted.status_code == 200, muted.text
        assert muted.json()["data"]["muted"] is True

        muted_history = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "history", "provider": "claude"},
                headers=headers,
            ),
            "inc-active",
        )
        muted_list = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "muted", "provider": "claude"},
                headers=headers,
            ),
            "inc-active",
        )
        assert muted_history["muted"] is True
        assert muted_history["revision"] == muted_list["revision"]
        assert muted_history["revision"] == muted.json()["data"]["revision"]

        from_history = client.delete(
            BASE + "/status-alerts/incidents/inc-active/mute",
            headers={**headers, "If-Match": muted_history["revision"]},
        )
        assert from_history.status_code == 204, from_history.text

        unmuted_history = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "history", "provider": "claude"},
                headers=headers,
            ),
            "inc-active",
        )
        assert unmuted_history["muted"] is False
        remuted = client.post(
            BASE + "/status-alerts/incidents/inc-active/actions/mute",
            headers={**headers, "If-Match": unmuted_history["revision"]},
        )
        assert remuted.status_code == 200, remuted.text

        current_muted = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "muted", "provider": "claude"},
                headers=headers,
            ),
            "inc-active",
        )
        from_muted = client.delete(
            BASE + "/status-alerts/incidents/inc-active/mute",
            headers={**headers, "If-Match": current_muted["revision"]},
        )
        assert from_muted.status_code == 204, from_muted.text

    assert gateway.mute_calls == [
        ("claude", "inc-active", "Active incident"),
        ("claude", "inc-active", "Active incident"),
    ]
    assert gateway.unmute_calls == [
        ("claude", "inc-active"),
        ("claude", "inc-active"),
    ]


def test_stale_revision_has_no_side_effect_and_missing_or_repeat_semantics_stay_stable(tmp_path):
    app, gateway = _build_status_app(tmp_path)
    with TestClient(app) as client:
        headers = bearer(create_session(client))
        history = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "history", "provider": "claude"},
                headers=headers,
            ),
            "inc-resolved",
        )

        resolved = next(
            row for row in gateway.recent["claude"] if row["id"] == "inc-resolved"
        )
        resolved["status"] = "monitoring"
        resolved["updated_at"] = "2026-01-01T02:05:00Z"
        changed_feed = client.post(
            BASE + "/status-alerts/incidents/inc-resolved/actions/mute",
            headers={**headers, "If-Match": history["revision"]},
        )
        assert changed_feed.status_code == 409, changed_feed.text
        assert changed_feed.json()["error"]["code"] == "REVISION_CONFLICT"
        assert gateway.mute_calls == []
        assert ("claude", "inc-resolved") not in gateway.muted

        current_history = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "history", "provider": "claude"},
                headers=headers,
            ),
            "inc-resolved",
        )
        assert current_history["revision"] != history["revision"]
        first = client.post(
            BASE + "/status-alerts/incidents/inc-resolved/actions/mute",
            headers={**headers, "If-Match": current_history["revision"]},
        )
        assert first.status_code == 200, first.text
        state_after_first = copy.deepcopy(gateway.muted)
        calls_after_first = list(gateway.mute_calls)

        stale = client.post(
            BASE + "/status-alerts/incidents/inc-resolved/actions/mute",
            headers={**headers, "If-Match": current_history["revision"]},
        )
        assert stale.status_code == 409, stale.text
        assert stale.json()["error"]["code"] == "REVISION_CONFLICT"
        assert gateway.muted == state_after_first
        assert gateway.mute_calls == calls_after_first

        repeated = client.post(
            BASE + "/status-alerts/incidents/inc-resolved/actions/mute",
            headers=headers,
        )
        assert repeated.status_code == 200, repeated.text
        assert len(gateway.mute_calls) == len(calls_after_first) + 1

        stale_unmute = client.delete(
            BASE + "/status-alerts/incidents/inc-resolved/mute",
            headers={**headers, "If-Match": first.json()["data"]["revision"]},
        )
        assert stale_unmute.status_code == 409, stale_unmute.text
        assert stale_unmute.json()["error"]["code"] == "REVISION_CONFLICT"
        assert gateway.unmute_calls == []

        current = _item(
            client.get(
                BASE + "/status-alerts/incidents",
                params={"view": "muted", "provider": "claude"},
                headers=headers,
            ),
            "inc-resolved",
        )
        assert client.delete(
            BASE + "/status-alerts/incidents/inc-resolved/mute",
            headers={**headers, "If-Match": current["revision"]},
        ).status_code == 204
        repeated_unmute = client.delete(
            BASE + "/status-alerts/incidents/inc-resolved/mute",
            headers=headers,
        )
        assert repeated_unmute.status_code == 404
        assert repeated_unmute.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
        assert gateway.unmute_calls == [("claude", "inc-resolved")]

        missing_mute = client.post(
            BASE + "/status-alerts/incidents/missing/actions/mute",
            headers=headers,
        )
        missing_unmute = client.delete(
            BASE + "/status-alerts/incidents/missing/mute",
            headers=headers,
        )
        assert missing_mute.status_code == 404
        assert missing_unmute.status_code == 404
        assert missing_mute.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
        assert missing_unmute.json()["error"]["code"] == "RESOURCE_NOT_FOUND"
        assert len(gateway.mute_calls) == len(calls_after_first) + 1
        assert gateway.unmute_calls == [("claude", "inc-resolved")]

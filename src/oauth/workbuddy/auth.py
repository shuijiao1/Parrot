"""WorkBuddy browser login, stored credential normalization and refresh."""
from __future__ import annotations

import copy
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

from . import common

ACCOUNT_FIELDS = (
    "realm", "uid", "enterprise_id", "domain", "nickname", "label",
    "workbuddy_client_profile", "workbuddy_identity_source", "workbuddy_auto_checkin",
)


def utc_text(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def identity(account: dict) -> str:
    realm = common.realm_of(account)
    uid = common.text(account.get("uid"), "uid", required=True)
    enterprise = common.text(account.get("enterprise_id"), "enterprise_id")
    scope = "e." + quote(enterprise, safe="") if enterprise else "p"
    return f"{realm}:{quote(uid, safe='')}:{scope}"


def _expiry(raw) -> str:
    if raw is None or raw == "":
        return ""
    try:
        if isinstance(raw, (float, int)) and not isinstance(raw, bool):
            return utc_text(float(raw)) if raw > 0 else ""
        if isinstance(raw, str):
            if raw.strip().replace(".", "", 1).isdigit():
                return utc_text(float(raw))
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if value.tzinfo is None:
                raise ValueError("timezone required")
            return utc_text(value.timestamp())
    except (ValueError, OverflowError, OSError):
        pass
    raise ValueError("Invalid WorkBuddy absolute token expiry")


def normalize_credential(value: dict, *, realm: str | None = None, source: str = "import") -> dict:
    if not isinstance(value, dict):
        raise ValueError("WorkBuddy credential must be an object")
    if value.get("provider", value.get("type", "workbuddy")) not in ("workbuddy", None, ""):
        raise ValueError("Credential belongs to another provider")
    auth = value.get("auth", value)
    account = value.get("account", value)
    if not isinstance(auth, dict) or not isinstance(account, dict):
        raise ValueError("Invalid WorkBuddy credential sections")
    declared = realm or value.get("realm") or auth.get("realm")
    if realm and value.get("realm") and realm != value["realm"]:
        raise ValueError("WorkBuddy import region mismatch")
    entry = {
        "provider": "workbuddy", "type": "workbuddy",
        "access_token": common.text(auth.get("access_token", auth.get("accessToken")), "access_token", required=True, maximum=32768),
        "refresh_token": common.text(auth.get("refresh_token", auth.get("refreshToken")), "refresh_token", required=True, maximum=32768),
        "uid": common.text(account.get("uid"), "uid", required=True),
        "enterprise_id": common.text(account.get("enterprise_id", account.get("enterpriseId")), "enterprise_id"),
        "domain": common.text(auth.get("domain", value.get("domain")), "domain"),
        "realm": declared or "",
        "nickname": common.text(account.get("nickname"), "nickname"),
        "email": common.text(account.get("email"), "email"),
        "workbuddy_client_profile": value.get("workbuddy_client_profile") or common.PROFILE,
        "workbuddy_identity_source": source,
    }
    entry["realm"] = common.realm_of(entry)
    entry["label"] = common.text(value.get("label"), "label") or entry["nickname"] or entry["uid"]
    absolute = auth.get("expired", auth.get("expires_at", auth.get("expiresAt")))
    # Relative expiresIn in a copied file has no acquisition time; never renew it on import.
    entry["expired"] = _expiry(absolute)
    if source == "login":
        entry["last_refresh"] = utc_text(time.time())
    identity(entry)  # Validate every identity component before publication.
    return entry


def start_login_sync(*, realm: str = "cn", client_profile: str | None = None) -> dict:
    profile = common.login_profile(realm, client_profile)
    cookies: dict = {}
    account = {"realm": realm, "workbuddy_client_profile": profile}
    platform = "ide" if profile == common.GLOBAL_PROFILE else "CLI"
    data = common.request(account, "/v2/plugin/auth/state?" + urlencode({"platform": platform}), body={},
                          kind="anonymous", cookies=cookies)
    return {**account, "state": common.text(data.get("state"), "state", required=True, maximum=4096),
            "auth_url": common.safe_auth_url(data.get("authUrl"), realm=realm), "cookies": cookies,
            "status": "pending"}


def poll_login_sync(payload: dict) -> dict:
    """One poll; retains obtained credentials when account lookup needs a retry.

    Caller serializes access to the flow. The returned entry is secret and must
    stay in the flow/control boundary, not a public response or audit payload.
    """
    if payload.get("status") == "ready":
        return copy.deepcopy(payload["entry"])
    account = {"realm": payload["realm"], "workbuddy_client_profile": common.login_profile(
        payload["realm"], payload.get("workbuddy_client_profile"),
    )}
    query = urlencode({"state": payload["state"]})
    cookies = payload.setdefault("cookies", {})
    if "token" not in payload:
        token = common.request(account, "/v2/plugin/auth/token?" + query, method="GET",
                               kind="anonymous", cookies=cookies, pending=True)
        if token is None or not token.get("accessToken"):
            payload["status"] = "pending"
            return {}
        common.text(token.get("refreshToken"), "refresh_token", required=True, maximum=32768)
        token = copy.deepcopy(token)
        seconds = common.number(token.get("expiresIn"))
        if seconds is not None and 0 < seconds <= 366 * 86400:
            token["expired"] = utc_text(time.time() + seconds)
        payload["token"] = token
        payload["status"] = "identity_pending"
    token = payload["token"]
    auth_account = dict(account, access_token=token["accessToken"], domain=token.get("domain") or "")
    common.realm_of(auth_account)  # Never send credentials across regions.
    info = common.request(auth_account, "/v2/plugin/login/account?" + query, method="GET",
                          kind="account", cookies=cookies)
    entry = normalize_credential({"auth": token, "account": info, **account}, source="login")
    payload.update(status="ready", entry=entry)
    payload.pop("token", None)
    return copy.deepcopy(entry)


def refresh_sync(refresh_token: str, *, account: dict, account_key: str = "") -> dict:
    common.require_refresh()
    options = {"body": {}} if common.profile_of(account) == common.GLOBAL_PROFILE else {}
    data = common.request(dict(account, refresh_token=refresh_token), "/v2/plugin/auth/token/refresh",
                          kind="refresh", account_key=account_key, **options)
    result = {"access_token": common.text(data.get("accessToken"), "access_token", required=True, maximum=32768)}
    if data.get("refreshToken"):
        result["refresh_token"] = common.text(data["refreshToken"], "refresh_token", required=True, maximum=32768)
    seconds = common.number(data.get("expiresIn"))
    if seconds is not None and 0 < seconds <= 366 * 86400:
        result["expires_in"] = seconds
    if data.get("domain"):
        candidate = dict(account, domain=data["domain"])
        common.realm_of(candidate)
        result["domain"] = common.text(data["domain"], "domain")
    return result

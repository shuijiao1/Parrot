"""Mechanical projection helpers for :mod:`src.openai.codex_identity`.

The authoritative public API remains in ``codex_identity``.  These helpers take
its concrete error/context types as arguments so this split introduces no import
cycle and keeps the original module's monkeypatch seams intact.
"""

from __future__ import annotations

from typing import Any, Mapping


def _drop_headers(headers: Mapping[str, Any], names: set[str]) -> dict[str, str]:
    lowered = {name.lower() for name in names}
    return {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).lower() not in lowered
    }


def project_snapshot(
    snapshot: Any,
    headers: Mapping[str, Any] | None,
    payload: Mapping[str, Any] | None,
    *,
    direct_installation_header: bool,
    create_client_metadata: bool,
    identity_error: type[ValueError],
) -> tuple[dict[str, str], dict[str, Any] | None]:
    """Implement projection for the public ``codex_identity`` wrapper."""
    out_headers = _drop_headers(
        headers or {},
        {
            "session_id", "conversation_id", "conversation-id",
            "session-id", "thread-id", "x-client-request-id",
            "x-codex-window-id", "x-codex-turn-metadata",
            "x-codex-turn-state", "x-codex-installation-id",
        },
    )
    metadata_json = snapshot.canonical_turn_metadata()
    out_headers.update({
        "session-id": snapshot.session_id,
        "thread-id": snapshot.thread_id,
        "x-client-request-id": snapshot.thread_id,
        "x-codex-window-id": snapshot.window_id,
        "x-codex-turn-metadata": metadata_json,
    })
    if snapshot.turn_state:
        out_headers["x-codex-turn-state"] = snapshot.turn_state
    if direct_installation_header:
        out_headers["x-codex-installation-id"] = snapshot.installation_id

    if payload is None:
        return out_headers, None
    out_payload: dict[str, Any] = {
        key: value for key, value in payload.items()
        if not (isinstance(key, str) and key.startswith("_"))
    }
    out_payload["prompt_cache_key"] = snapshot.prompt_cache_key
    current_metadata = out_payload.get("client_metadata")
    if current_metadata is not None and not isinstance(current_metadata, Mapping):
        raise identity_error("client_metadata must be an object for Codex identity")
    if current_metadata is None and not create_client_metadata:
        return out_headers, out_payload
    metadata = dict(current_metadata or {})
    for key in (
        "x-codex-installation-id", "session_id", "thread_id", "turn_id",
        "x-codex-window-id", "x-codex-turn-metadata", "x-codex-turn-state",
    ):
        metadata.pop(key, None)
    metadata.update({
        "x-codex-installation-id": snapshot.installation_id,
        "session_id": snapshot.session_id,
        "thread_id": snapshot.thread_id,
        "turn_id": snapshot.turn_id,
        "x-codex-window-id": snapshot.window_id,
        "x-codex-turn-metadata": metadata_json,
    })
    if snapshot.turn_state:
        metadata["x-codex-turn-state"] = snapshot.turn_state
    out_payload["client_metadata"] = metadata
    return out_headers, out_payload


def capture_turn_state(
    translator_ctx: Mapping[str, Any] | None,
    headers: Any,
    *,
    request_context_type: type,
    snapshot_type: type,
) -> bool:
    """Implement scoped state capture for the public identity wrapper."""
    if not isinstance(translator_ctx, Mapping):
        return False
    context = translator_ctx.get("codex_identity_context")
    snapshot = translator_ctx.get("codex_identity_snapshot")
    if not isinstance(context, request_context_type) or not isinstance(
        snapshot, snapshot_type
    ):
        return False
    token = ""
    # ``websockets.Headers.items()`` raises when an unrelated header (notably
    # Set-Cookie) legally occurs more than once. Read only the target field and
    # reject an ambiguous repeated turn-state instead of enumerating all headers.
    if hasattr(headers, "get_all"):
        try:
            values = list(headers.get_all("x-codex-turn-state"))
        except Exception:
            values = []
        if len(values) == 1:
            token = str(values[0])
    elif isinstance(headers, Mapping):
        values = [
            value for key, value in headers.items()
            if str(key).lower() == "x-codex-turn-state"
        ]
        if len(values) == 1:
            token = str(values[0])
    elif hasattr(headers, "get"):
        try:
            token = str(headers.get("x-codex-turn-state") or "")
        except Exception:
            token = ""
    elif hasattr(headers, "items"):
        for key, value in headers.items():
            if str(key).lower() == "x-codex-turn-state":
                token = str(value)
                break
    return context.turn.capture_turn_state(
        token,
        owner_digest=snapshot.owner_digest,
        turn_id=snapshot.turn_id,
    )

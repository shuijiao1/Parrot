"""Provider-owned public names for ambiguous OAuth model IDs.

Only these explicit IDs are aliased. Stored/upstream IDs remain untouched;
resolution happens inside the owning channel, never in the global model map.
"""
from __future__ import annotations

_PROVIDERS = frozenset({"workbuddy", "cursor"})
_GENERIC_IDS = frozenset({"auto", "default"})
_PUBLIC_TO_UPSTREAM = {f"{provider}-{model}": (provider, model)
                       for provider in _PROVIDERS for model in _GENERIC_IDS}


def public_id(provider: str, model: str) -> str:
    return f"{provider}-{model}" if provider in _PROVIDERS and model in _GENERIC_IDS else model


def upstream_id(provider: str, model: str) -> str:
    pair = _PUBLIC_TO_UPSTREAM.get(model)
    return pair[1] if pair is not None and pair[0] == provider else model


def display_name(provider: str, model: str, name: str | None = None) -> str:
    # The generic upstream display name is just as ambiguous as its ID.
    return public_id(provider, model) if public_id(provider, model) != model else (name or model)


def _channel_provider(channel_key: str) -> str:
    parts = str(channel_key or "").split(":", 2)
    return parts[1] if len(parts) >= 2 and parts[0] == "oauth" else ""


def for_channel(channel_key: str, model: str) -> str:
    return public_id(_channel_provider(channel_key), model)


def upstream_for_channel(channel_key: str, model: str) -> str:
    return upstream_id(_channel_provider(channel_key), model)


def expand_legacy_permissions(models: list[str]) -> list[str]:
    """Old raw-ID grants keep covering their renamed models, not the reverse.

    A new cursor-default-only grant must NOT authorize bare default or
    workbuddy-default. No persisted API-key grant is changed here.
    """
    result = list(models)
    for alias, (_provider, upstream) in sorted(_PUBLIC_TO_UPSTREAM.items()):
        if upstream in models and alias not in result:
            result.append(alias)
    return result


def response_context(provider: str, upstream_model: str, context: dict | None,
                     *, ingress: str) -> dict | None:
    public = public_id(provider, upstream_model)
    if public == upstream_model:
        return context
    result = dict(context or {})
    result["model_for_response"] = public
    result["response_model_override"] = public
    if not result.get("response_translator"):
        # Both providers speak Chat upstream. Cross-protocol translators already
        # own their output model field; same-protocol Chat needs only this view.
        result.update(response_translator="chat_model_alias", ingress=ingress,
                      upstream_protocol="openai-chat")
    return result

"""Authenticated, account-scoped WorkBuddy CLI model discovery."""
from __future__ import annotations

from . import common


def fetch_models_sync(account: dict, *, account_key: str = "", timeout: float = 20.0) -> list[dict]:
    data = common.request(account, "/console/enterprises/personal/models", method="GET",
                          kind="account", account_key=account_key, timeout=timeout)
    models, agents = data.get("models"), data.get("agents")
    if not isinstance(models, list) or not isinstance(agents, list):
        raise common.WorkBuddyError("models", kind="invalid_catalog")
    # Prefer an explicitly advertised IDE catalog for the international profile;
    # gateways exposing the shared CLI catalog retain that authenticated filter.
    agent_name = "ide" if common.profile_of(account) == common.GLOBAL_PROFILE and any(
        isinstance(agent, dict) and agent.get("name") == "ide" for agent in agents
    ) else "cli"
    client_models = next((agent.get("models") for agent in agents if isinstance(agent, dict) and agent.get("name") == agent_name), None)
    if not isinstance(client_models, list) or not client_models:
        raise common.WorkBuddyError("models", kind=f"missing_{agent_name}_catalog")
    entries = {item["id"]: item for item in models if isinstance(item, dict) and isinstance(item.get("id"), str)}
    records = []
    seen = set()
    for model_id in client_models:
        if not isinstance(model_id, str) or model_id not in entries or model_id in seen:
            continue
        source = entries[model_id]
        if source.get("disabled") is True:
            continue
        common.text(model_id, "model", required=True, maximum=256)
        seen.add(model_id)
        record = {"id": model_id, "name": common.text(source.get("name") or model_id, "model name"),
                  "source": f"workbuddy:{agent_name}", "inputModalities": ["text"], "outputModalities": ["text"]}
        for source_key, target in (("maxInputTokens", "maxInputTokens"), ("maxOutputTokens", "maxOutputTokens")):
            value = common.number(source.get(source_key))
            if isinstance(value, int) and value > 0:
                record[target] = value
        reasoning = source.get("reasoning")
        efforts = reasoning.get("supportedEfforts") if isinstance(reasoning, dict) else None
        if isinstance(efforts, list):
            record["reasoningEfforts"] = list(dict.fromkeys(
                item for item in efforts if isinstance(item, str) and item in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
            ))
        records.append(record)
    if not records:
        raise common.WorkBuddyError("models", kind="empty_catalog")
    return records

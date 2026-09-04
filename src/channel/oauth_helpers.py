"""Shared helpers for OAuth-backed channels."""


def request_api_key_name(body: dict) -> str:
    """Return the downstream API key name for OpenAI or Anthropic ingress.

    OpenAI handlers inject ``_api_key_name`` while the Anthropic /v1/messages
    route injects ``_parrot_api_key_name``. OAuth channel session isolation and
    cross-protocol prompt-cache keys treat them equivalently.
    """
    return str(body.get("_api_key_name") or body.get("_parrot_api_key_name") or "")

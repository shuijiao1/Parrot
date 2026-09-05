"""Public OAuth account IDs versus internal routing channel keys.

Management API resources expose the canonical account key returned by OAuth
endpoints.  Registry, metadata bindings and proxy routing continue to store the
same key with their historical ``oauth:`` channel prefix.
"""

from __future__ import annotations


_OAUTH_CHANNEL_PREFIX = "oauth:"


def oauth_channel_key_from_account_id(account_id: str) -> str:
    """Map a public accountId to its internal OAuth channel key.

    Already-prefixed values remain accepted as a compatibility input for early
    Management API clients, but new API output never requires that prefix.
    """
    value = str(account_id)
    if value.startswith(_OAUTH_CHANNEL_PREFIX):
        return value
    return f"{_OAUTH_CHANNEL_PREFIX}{value}"


def oauth_account_id_from_channel_key(channel_key: str) -> str:
    """Map an internal OAuth channel key back to the public canonical accountId."""
    value = str(channel_key)
    if value.startswith(_OAUTH_CHANNEL_PREFIX):
        return value[len(_OAUTH_CHANNEL_PREFIX):]
    return value

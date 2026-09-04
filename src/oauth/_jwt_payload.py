"""Shared unsigned JWT payload decoding for OAuth providers."""


def decode_jwt_payload(
    id_token: str,
    verify_exp: bool,
    skew_seconds: int,
    error_type: type[ValueError],
    base64_module,
    json_module,
    time_module,
) -> dict:
    """Decode payload while leaving errors and dependency seams provider-owned."""
    if not id_token or id_token.count(".") < 2:
        raise error_type(f"invalid JWT: got {id_token!r}")
    parts = id_token.split(".")
    if len(parts) != 3:
        raise error_type(f"invalid JWT: expected 3 parts, got {len(parts)}")
    payload_b64 = parts[1]
    padding = (-len(payload_b64)) % 4
    if padding:
        payload_b64 += "=" * padding
    try:
        raw = base64_module.urlsafe_b64decode(payload_b64)
    except Exception as exc:
        raise error_type(f"decode base64: {exc}") from exc
    try:
        claims = json_module.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise error_type(f"parse JSON: {exc}") from exc
    if verify_exp:
        exp = claims.get("exp")
        if isinstance(exp, int) and exp > 0 and time_module.time() > exp + skew_seconds:
            raise error_type(f"id_token expired (exp={exp})")
    return claims

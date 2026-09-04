"""Neutral response helpers shared by Management API adapters."""

from __future__ import annotations

from fastapi import Request

from .dependencies import management_request_id
from .schemas.base import ResponseMeta


def response_meta(request: Request) -> ResponseMeta:
    return ResponseMeta(requestId=management_request_id(request))


def success_response(code: int, data: dict | list) -> dict[int, dict]:
    meta: dict[str, object] = {"requestId": "request-example"}
    if isinstance(data, list):
        meta.update({
            "page": 1,
            "pageSize": 50,
            "total": len(data),
            "hasNext": False,
            "revision": "rev_example",
        })
    return {
        code: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"data": data, "meta": meta}}},
        }
    }

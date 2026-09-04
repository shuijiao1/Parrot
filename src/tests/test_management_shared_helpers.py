from __future__ import annotations

import pytest
from starlette.requests import Request

from src.management_api.response_helpers import response_meta, success_response
from src.management_api.routers import (
    apikey,
    auxiliary_support,
    channels,
    foundation,
    load_balancing,
    mapping,
    model_metadata,
    proxy,
    system_support,
)
from src.management_control import ManagementError, ManagementErrorCode
from src.management_control.dependency_mapping import dependency_result
from src.management_control.network import NetworkControl
from src.management_control.system import ContentBlacklistControl, SettingsControl


def test_controls_share_dependency_mapper_and_preserve_failure_boundary():
    controls = (NetworkControl, SettingsControl, ContentBlacklistControl)
    assert all(control._dependency is dependency_result for control in controls)

    calls = []
    assert dependency_result(lambda: calls.append("success") or "value") == "value"
    assert calls == ["success"]

    raw = RuntimeError("private dependency detail")

    def fail():
        calls.append("failure")
        raise raw

    with pytest.raises(ManagementError) as caught:
        dependency_result(fail)
    assert calls == ["success", "failure"]
    assert caught.value.code is ManagementErrorCode.DEPENDENCY_UNAVAILABLE
    assert caught.value.message == "A required dependency is unavailable"
    assert caught.value.retryable is True
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_model_routers_share_exact_success_response_metadata():
    assert mapping._success is success_response
    assert model_metadata._success is success_response
    assert proxy._success is success_response

    item = {"revision": "rev_example"}
    assert success_response(201, item) == {
        201: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "data": item,
                        "meta": {"requestId": "request-example"},
                    }
                }
            },
        }
    }
    items = [item]
    response = success_response(200, items)
    assert response == {
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "data": items,
                        "meta": {
                            "requestId": "request-example",
                            "page": 1,
                            "pageSize": 50,
                            "total": 1,
                            "hasNext": False,
                            "revision": "rev_example",
                        },
                    }
                }
            },
        }
    }
    meta = response[200]["content"]["application/json"]["example"]["meta"]
    assert list(meta) == [
        "requestId", "page", "pageSize", "total", "hasNext", "revision",
    ]


def test_ordinary_routers_share_response_meta_without_touching_special_meta():
    helpers = (
        apikey._meta,
        auxiliary_support.response_meta,
        channels._meta,
        foundation._meta,
        load_balancing._meta,
        mapping._meta,
        model_metadata._meta,
        proxy._meta,
        system_support.response_meta,
    )
    assert all(helper is response_meta for helper in helpers)

    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-request-id", b"shared-helper-request")],
    })
    assert response_meta(request).model_dump() == {
        "requestId": "shared-helper-request",
    }

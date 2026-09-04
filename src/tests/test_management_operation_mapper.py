from __future__ import annotations

import json
from datetime import datetime, timezone

from src.management_api.routers import (
    _observability,
    auxiliary_support,
    channels,
    foundation,
    model_metadata,
    oauth_support,
    proxy,
    system_support,
)
from src.management_api.routers._operations import operation_data
from src.management_control import ManagementErrorCode
from src.management_control.operations import (
    ManagementOperation,
    OperationFailure,
    OperationProgress,
    OperationStatus,
)


def test_all_ordinary_operation_adapters_share_the_exact_mapper():
    assert (
        _observability.operation_data
        is auxiliary_support.operation_data
        is channels._operation_data
        is foundation._operation_data
        is model_metadata._operation
        is proxy._operation
        is system_support.operation_data
        is operation_data
    )
    assert oauth_support.operation is not operation_data


def test_ordinary_operation_mapper_preserves_every_public_field_and_json_format():
    created_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    started_at = datetime(2026, 1, 2, 3, 4, 6, tzinfo=timezone.utc)
    finished_at = datetime(2026, 1, 2, 3, 4, 7, tzinfo=timezone.utc)
    result = {"state": "unchanged", "nested": [1, True, None]}
    operation = ManagementOperation(
        id="op_example",
        kind="domain.refresh",
        status=OperationStatus.FAILED,
        actor_subject_id="administrator",
        session_id="session-example",
        progress=OperationProgress(current=2, total=3, message_code="step.two"),
        created_at=created_at,
        started_at=started_at,
        finished_at=finished_at,
        result=result,
        error=OperationFailure(
            code=ManagementErrorCode.UPSTREAM_ERROR,
            message="public failure text",
            retryable=True,
        ),
        cancellable=False,
    )

    mapped = operation_data(operation)

    assert mapped.createdAt is created_at
    assert mapped.startedAt is started_at
    assert mapped.finishedAt is finished_at
    assert mapped.result == result
    assert json.loads(mapped.model_dump_json()) == {
        "id": "op_example",
        "kind": "domain.refresh",
        "status": "failed",
        "progress": {"current": 2, "total": 3, "messageCode": "step.two"},
        "createdAt": "2026-01-02T03:04:05Z",
        "startedAt": "2026-01-02T03:04:06Z",
        "finishedAt": "2026-01-02T03:04:07Z",
        "result": result,
        "error": {
            "code": "UPSTREAM_ERROR",
            "message": "public failure text",
            "retryable": True,
        },
        "cancellable": False,
    }

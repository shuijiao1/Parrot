"""Multimedia log and cached-artifact endpoints."""

from datetime import datetime
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import StreamingResponse

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode
from src.management_control.observability import MediaAction, MediaLogQuery, MediaSort, MediaStatus

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas import DataEnvelope
from ..schemas.observability import MediaArtifactData, MediaLogData, MediaLogDetailData, PagedEnvelope
from ._observability import controls, meta, paged_meta, reject_unknown_query


router = APIRouter(prefix="/media-logs", tags=["management-media"])
_ERRORS = management_error_responses(
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.CAPABILITY_DENIED, ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.RESOURCE_NOT_FOUND, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
)


@router.get(
    "", operation_id="listMediaLogs",
    response_model=PagedEnvelope[MediaLogData], responses=_ERRORS,
)
def list_media_logs(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    status: Annotated[list[MediaStatus] | None, Query()] = None,
    provider: Annotated[list[str] | None, Query()] = None,
    model: Annotated[list[str] | None, Query()] = None,
    action: Annotated[list[MediaAction] | None, Query()] = None,
    started_at: Annotated[datetime | None, Query(alias="startedAt")] = None,
    ended_at: Annotated[datetime | None, Query(alias="endedAt")] = None,
    sort: Annotated[MediaSort, Query()] = MediaSort.CREATED_AT,
    descending: Annotated[bool, Query()] = True,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(alias="pageSize", ge=1, le=200)] = 50,
) -> PagedEnvelope[MediaLogData]:
    reject_unknown_query(request, (
        "status", "provider", "model", "action", "startedAt", "endedAt",
        "sort", "descending", "page", "pageSize",
    ))
    result = controls(request).media.list_logs(context, MediaLogQuery(
        statuses=tuple(status or ()), providers=tuple(provider or ()), models=tuple(model or ()),
        actions=tuple(action or ()), started_at=started_at, ended_at=ended_at,
        sort=sort, descending=descending, page=page, page_size=page_size,
    ))
    return PagedEnvelope(data=[MediaLogData.model_validate(item) for item in result.items], meta=paged_meta(request, result))


@router.get(
    "/{mediaLogId}/artifacts", operation_id="listMediaArtifacts",
    response_model=DataEnvelope[list[MediaArtifactData]], responses=_ERRORS,
)
def list_media_artifacts(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    media_log_id: Annotated[str, Path(alias="mediaLogId", min_length=1, max_length=128)],
) -> DataEnvelope[list[MediaArtifactData]]:
    reject_unknown_query(request, ())
    values = controls(request).media.artifacts(context, media_log_id)
    return DataEnvelope(data=[MediaArtifactData.model_validate(item) for item in values], meta=meta(request))


@router.get(
    "/{mediaLogId}/artifacts/{artifactId}", operation_id="downloadMediaArtifact",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "Authenticated cached media artifact",
            "content": {"application/octet-stream": {"example": "<binary>"}},
        },
        **_ERRORS,
    },
)
def download_media_artifact(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    media_log_id: Annotated[str, Path(alias="mediaLogId", min_length=1, max_length=128)],
    artifact_id: Annotated[str, Path(alias="artifactId", min_length=1, max_length=128)],
) -> StreamingResponse:
    reject_unknown_query(request, ())
    artifact = controls(request).media.download(context, media_log_id, artifact_id)
    filename = quote(artifact.filename, safe="")
    return StreamingResponse(
        artifact.chunks,
        media_type=artifact.content_type,
        headers={
            "Content-Length": str(artifact.size),
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
            "Cache-Control": "private, no-store",
        },
    )


@router.get(
    "/{mediaLogId}", operation_id="getMediaLog",
    response_model=DataEnvelope[MediaLogDetailData], responses=_ERRORS,
)
def get_media_log(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
    media_log_id: Annotated[str, Path(alias="mediaLogId", min_length=1, max_length=128)],
) -> DataEnvelope[MediaLogDetailData]:
    reject_unknown_query(request, ())
    value = controls(request).media.detail(context, media_log_id)
    return DataEnvelope(data=MediaLogDetailData.model_validate(value), meta=meta(request))

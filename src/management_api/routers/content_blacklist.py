"""Content blacklist Management API routes."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Header, Path, Request, Response, status

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas.base import DataEnvelope
from ..schemas.system import BlacklistTermRequest, ContentBlacklistData
from .system_support import (
    SystemNetworkControls,
    get_bound_system_network_controls,
    reject_unknown_query,
    response_meta,
    success_response,
)


router = APIRouter()
ReadContext = Annotated[ManagementContext, Depends(require_capability(Capability.READ))]
WriteContext = Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))]
DestroyContext = Annotated[ManagementContext, Depends(require_capability(Capability.DESTRUCTIVE))]
Controls = Annotated[SystemNetworkControls, Depends(get_bound_system_network_controls)]
IfMatch = Annotated[str | None, Header(alias="If-Match")]
_EXAMPLE = {
    "default": ["policy_violation"],
    "byChannel": [{"channelId": "api:example", "terms": ["blocked_prefix"]}],
    "revision": "rev_example",
}
_ERRORS = (
    ManagementErrorCode.SESSION_REQUIRED, ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.ORIGIN_DENIED, ManagementErrorCode.CAPABILITY_DENIED,
    ManagementErrorCode.VALIDATION_FAILED, ManagementErrorCode.RESOURCE_NOT_FOUND,
    ManagementErrorCode.REVISION_CONFLICT, ManagementErrorCode.DEPENDENCY_UNAVAILABLE,
    ManagementErrorCode.SERVICE_NOT_READY,
)
_RESPONSES = {**success_response(200, _EXAMPLE), **management_error_responses(*_ERRORS)}
_CREATE_RESPONSES = {**success_response(201, _EXAMPLE), **management_error_responses(*_ERRORS)}


def _data(value) -> ContentBlacklistData:
    return ContentBlacklistData.model_validate(asdict(value))


def _raw_channel_term(request: Request) -> tuple[str, str]:
    """Split encoded DELETE segments before ASGI's percent-decoding loses `/`."""
    raw_path = bytes(request.scope.get("raw_path") or b"").decode("latin-1")
    marker = "/content-blacklist/channels/"
    encoded = raw_path.split(marker, 1)[-1]
    channel, separator, term = encoded.partition("/")
    if not separator:
        return "", ""
    return unquote(channel), unquote(term)


@router.get(
    "/content-blacklist", operation_id="getContentBlacklist",
    dependencies=[Depends(reject_unknown_query())], tags=["management-system"],
    response_model=DataEnvelope[ContentBlacklistData], responses=_RESPONSES,
)
def get_content_blacklist(request: Request, context: ReadContext, controls: Controls):
    return DataEnvelope(data=_data(controls.blacklist.get(context)), meta=response_meta(request))


@router.post(
    "/content-blacklist/default", operation_id="addDefaultBlacklistTerm",
    dependencies=[Depends(reject_unknown_query())], tags=["management-system"],
    status_code=status.HTTP_201_CREATED,
    response_model=DataEnvelope[ContentBlacklistData], responses=_CREATE_RESPONSES,
)
def add_default_blacklist_term(body: BlacklistTermRequest, request: Request, context: WriteContext, controls: Controls, if_match: IfMatch = None):
    value = controls.blacklist.add_default(context, body.term, expected_revision=if_match)
    return DataEnvelope(data=_data(value), meta=response_meta(request))


@router.delete(
    "/content-blacklist/default/{term:path}", operation_id="deleteDefaultBlacklistTerm",
    dependencies=[Depends(reject_unknown_query())], tags=["management-system"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={204: {"description": "Blacklist term removed"}, **management_error_responses(*_ERRORS)},
)
def delete_default_blacklist_term(
    term: Annotated[str, Path(min_length=1, max_length=200)], context: DestroyContext,
    controls: Controls, if_match: IfMatch = None,
) -> Response:
    controls.blacklist.delete_default(context, term, expected_revision=if_match)
    return Response(status_code=204)


@router.post(
    "/content-blacklist/channels/{channelId:path}", operation_id="addChannelBlacklistTerm",
    dependencies=[Depends(reject_unknown_query())], tags=["management-system"],
    status_code=status.HTTP_201_CREATED,
    response_model=DataEnvelope[ContentBlacklistData], responses=_CREATE_RESPONSES,
)
def add_channel_blacklist_term(
    channel_id: Annotated[str, Path(alias="channelId", min_length=1, max_length=512)],
    body: BlacklistTermRequest, request: Request, context: WriteContext,
    controls: Controls, if_match: IfMatch = None,
):
    value = controls.blacklist.add_channel(context, channel_id, body.term, expected_revision=if_match)
    return DataEnvelope(data=_data(value), meta=response_meta(request))


@router.delete(
    "/content-blacklist/channels/{channelId:path}/{term:path}", operation_id="deleteChannelBlacklistTerm",
    dependencies=[Depends(reject_unknown_query())], tags=["management-system"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={204: {"description": "Channel blacklist term removed"}, **management_error_responses(*_ERRORS)},
)
def delete_channel_blacklist_term(
    request: Request,
    channel_id: Annotated[str, Path(alias="channelId", min_length=1, max_length=512)],
    term: Annotated[str, Path(min_length=1, max_length=200)], context: DestroyContext,
    controls: Controls, if_match: IfMatch = None,
) -> Response:
    raw_channel, raw_term = _raw_channel_term(request)
    controls.blacklist.delete_channel(
        context, raw_channel or channel_id, raw_term or term,
        expected_revision=if_match,
    )
    return Response(status_code=204)

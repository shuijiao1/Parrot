"""GPT image and xAI media settings Management API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Request

from src.management_auth.principal import Capability
from src.management_control import ManagementContext, ManagementErrorCode
from src.management_control.auxiliary import AuxiliaryControls

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas.base import DataEnvelope
from ..schemas.auxiliary_media import (
    ImageAccountStateData,
    ImageAccountStatePatch,
    ImageSettingsData,
    ImageSettingsPatch,
    XaiMediaSettingsData,
    XaiMediaSettingsPatch,
)
from .auxiliary_support import (
    get_bound_auxiliary_controls,
    reject_unknown_query,
    response_meta,
    success_response,
)


router = APIRouter()

_IMAGE_EXAMPLE = {
    "data": {
        "enabled": True,
        "cacheEnabled": False,
        "mainModel": "gpt-5.4-mini",
        "toolModel": "gpt-image-2",
        "cachePath": "images",
        "cacheRetentionDays": 30,
        "cacheMaxBytes": 1073741824,
        "revision": "rev_example",
    },
    "meta": {"requestId": "request-example"},
}
_ACCOUNT_EXAMPLE = {
    "data": {
        "accountId": "openai:account@example.com",
        "email": "account@example.com",
        "oauthEnabled": True,
        "imageEnabled": True,
        "imageCooldownUntil": None,
        "missingAccountId": False,
        "revision": "rev_example",
    },
    "meta": {"requestId": "request-example"},
}
_XAI_EXAMPLE = {
    "data": {
        "imageModels": ["grok-imagine-image"],
        "videoModels": ["grok-imagine-video"],
        "jobTtlSeconds": 10800,
        "requestTimeoutSeconds": 180,
        "revision": "rev_example",
    },
    "meta": {"requestId": "request-example"},
}
_ERRORS = (
    ManagementErrorCode.SESSION_REQUIRED,
    ManagementErrorCode.SESSION_EXPIRED,
    ManagementErrorCode.ORIGIN_DENIED,
    ManagementErrorCode.CAPABILITY_DENIED,
    ManagementErrorCode.RESOURCE_NOT_FOUND,
    ManagementErrorCode.REVISION_CONFLICT,
    ManagementErrorCode.VALIDATION_FAILED,
    ManagementErrorCode.SERVICE_NOT_READY,
)


def _image(value) -> ImageSettingsData:
    return ImageSettingsData(
        enabled=value.enabled,
        cacheEnabled=value.cache_enabled,
        mainModel=value.main_model,
        toolModel=value.tool_model,
        cachePath=value.cache_path,
        cacheRetentionDays=value.cache_retention_days,
        cacheMaxBytes=value.cache_max_bytes,
        revision=value.revision,
    )


def _account(value) -> ImageAccountStateData:
    return ImageAccountStateData(
        accountId=value.account_id,
        email=value.email,
        oauthEnabled=value.oauth_enabled,
        imageEnabled=value.image_enabled,
        imageCooldownUntil=value.image_cooldown_until,
        missingAccountId=value.missing_account_id,
        revision=value.revision,
    )


def _xai(value) -> XaiMediaSettingsData:
    return XaiMediaSettingsData(
        imageModels=list(value.image_models),
        videoModels=list(value.video_models),
        jobTtlSeconds=value.job_ttl_seconds,
        requestTimeoutSeconds=value.request_timeout_seconds,
        revision=value.revision,
    )


@router.get(
    "/images/settings",
    operation_id="getImageSettings",
    dependencies=[Depends(reject_unknown_query())],
    tags=["images"],
    response_model=DataEnvelope[ImageSettingsData],
    responses={**success_response(200, _IMAGE_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def get_image_settings(
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[ImageSettingsData]:
    return DataEnvelope(data=_image(controls.images.get_settings(context)), meta=response_meta(request))


@router.patch(
    "/images/settings",
    operation_id="updateImageSettings",
    dependencies=[Depends(reject_unknown_query())],
    tags=["images"],
    response_model=DataEnvelope[ImageSettingsData],
    responses={**success_response(200, _IMAGE_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def update_image_settings(
    body: ImageSettingsPatch,
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> DataEnvelope[ImageSettingsData]:
    value = controls.images.update_settings(
        context,
        body.model_dump(exclude_unset=True),
        expected_revision=if_match,
    )
    return DataEnvelope(data=_image(value), meta=response_meta(request))


@router.get(
    "/images/accounts/{accountId}",
    operation_id="getImageAccountState",
    dependencies=[Depends(reject_unknown_query())],
    tags=["images"],
    response_model=DataEnvelope[ImageAccountStateData],
    responses={**success_response(200, _ACCOUNT_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def get_image_account_state(
    account_id: Annotated[str, Path(alias="accountId", min_length=1, max_length=512)],
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[ImageAccountStateData]:
    return DataEnvelope(data=_account(controls.images.get_account(context, account_id)), meta=response_meta(request))


@router.patch(
    "/images/accounts/{accountId}",
    operation_id="updateImageAccountState",
    dependencies=[Depends(reject_unknown_query())],
    tags=["images"],
    response_model=DataEnvelope[ImageAccountStateData],
    responses={**success_response(200, _ACCOUNT_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def update_image_account_state(
    account_id: Annotated[str, Path(alias="accountId", min_length=1, max_length=512)],
    body: ImageAccountStatePatch,
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> DataEnvelope[ImageAccountStateData]:
    value = controls.images.update_account(
        context,
        account_id,
        enabled=body.enabled,
        expected_revision=if_match,
    )
    return DataEnvelope(data=_account(value), meta=response_meta(request))


@router.get(
    "/xai/media-settings",
    operation_id="getXaiMediaSettings",
    dependencies=[Depends(reject_unknown_query())],
    tags=["xai-media"],
    response_model=DataEnvelope[XaiMediaSettingsData],
    responses={**success_response(200, _XAI_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def get_xai_media_settings(
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[XaiMediaSettingsData]:
    return DataEnvelope(data=_xai(controls.xai_media.get_settings(context)), meta=response_meta(request))


@router.patch(
    "/xai/media-settings",
    operation_id="updateXaiMediaSettings",
    dependencies=[Depends(reject_unknown_query())],
    tags=["xai-media"],
    response_model=DataEnvelope[XaiMediaSettingsData],
    responses={**success_response(200, _XAI_EXAMPLE), **management_error_responses(*_ERRORS)},
)
def update_xai_media_settings(
    body: XaiMediaSettingsPatch,
    request: Request,
    controls: Annotated[AuxiliaryControls, Depends(get_bound_auxiliary_controls)],
    context: Annotated[ManagementContext, Depends(require_capability(Capability.WRITE))],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> DataEnvelope[XaiMediaSettingsData]:
    value = controls.xai_media.update_settings(
        context,
        body.model_dump(exclude_unset=True),
        expected_revision=if_match,
    )
    return DataEnvelope(data=_xai(value), meta=response_meta(request))

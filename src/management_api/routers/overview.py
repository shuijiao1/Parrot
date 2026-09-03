"""Management overview endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from src.management_auth import Capability
from src.management_control import ManagementContext, ManagementErrorCode

from ..dependencies import require_capability
from ..error_mapping import management_error_responses
from ..schemas import DataEnvelope
from ..schemas.observability import OverviewData
from ._observability import controls, meta, reject_unknown_query


router = APIRouter(tags=["management-overview"])


@router.get(
    "/overview",
    operation_id="getManagementOverview",
    response_model=DataEnvelope[OverviewData],
    responses=management_error_responses(
        ManagementErrorCode.SESSION_REQUIRED,
        ManagementErrorCode.SESSION_EXPIRED,
        ManagementErrorCode.CAPABILITY_DENIED,
        ManagementErrorCode.VALIDATION_FAILED,
        ManagementErrorCode.SERVICE_NOT_READY,
    ),
)
def get_management_overview(
    request: Request,
    context: Annotated[ManagementContext, Depends(require_capability(Capability.READ))],
) -> DataEnvelope[OverviewData]:
    reject_unknown_query(request, ())
    value = controls(request).status.overview(context)
    return DataEnvelope(data=OverviewData.model_validate(value), meta=meta(request))

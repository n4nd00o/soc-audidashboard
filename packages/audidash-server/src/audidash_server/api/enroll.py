"""POST /enroll: exchange a one-time enrollment token and a CSR for a client certificate.

Served on the enrollment listener (port 8443), which does not require a client certificate.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from audidash_server.api.deps import Db, get_ca
from audidash_server.ca import CA
from audidash_server.services.enrollment import EnrollmentError, enroll_device

router = APIRouter()


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$")
    csr_pem: str = Field(min_length=1, max_length=8192)


class EnrollResponse(BaseModel):
    device_id: str
    cert_pem: str
    ca_pem: str


@router.post("/enroll", status_code=201)
def enroll(body: EnrollRequest, db: Db, ca: Annotated[CA, Depends(get_ca)]) -> EnrollResponse:
    try:
        result = enroll_device(
            db, ca, token=body.token, device_name=body.device_name, csr_pem=body.csr_pem
        )
    except EnrollmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
    return EnrollResponse(
        device_id=str(result.device_id), cert_pem=result.cert_pem, ca_pem=result.ca_pem
    )

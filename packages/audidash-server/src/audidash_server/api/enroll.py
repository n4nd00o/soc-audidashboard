"""POST /enroll: exchange a one-time enrollment token and a CSR for a client certificate.

Served on the enrollment listener (port 8443), which does not require a client certificate.
`GET /ca.pem` publishes the CA certificate for the client's first-contact check.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
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


@router.get("/ca.pem")
def ca_certificate(ca: Annotated[CA, Depends(get_ca)]) -> Response:
    """The internal CA certificate (public, unauthenticated) for first-contact verification.

    The CLI downloads it without TLS verification, compares its SHA-256 with the fingerprint
    the administrator handed out and only then sends the enrolment token, over TLS verified
    against this CA (the dashboard listener's certificate is issued by it).
    """
    return Response(
        ca.cert_pem, media_type="application/x-pem-file", headers={"Cache-Control": "no-store"}
    )


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

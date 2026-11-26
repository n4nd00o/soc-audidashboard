"""Enrollment tokens and device enrollment (CSR -> client certificate)."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from audidash_server import audit, clock
from audidash_server.ca import CA, cert_fingerprint
from audidash_server.models import Device, EnrollmentToken

ENROLLMENT_TOKEN_TTL = timedelta(hours=24)


class EnrollmentError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_enrollment_token(
    db: DbSession, created_by: uuid.UUID, ttl: timedelta = ENROLLMENT_TOKEN_TTL
) -> str:
    """Add a single-use token row, 24 h by default (caller commits); return the only copy."""
    token = secrets.token_urlsafe(32)
    db.add(
        EnrollmentToken(
            token_sha256=token_sha256(token),
            created_by=created_by,
            expires_at=clock.now() + ttl,
        )
    )
    return token


@dataclass(frozen=True)
class Enrollment:
    device_id: uuid.UUID
    cert_pem: str
    ca_pem: str


def enroll_device(
    db: DbSession, ca: CA, *, token: str, device_name: str, csr_pem: str
) -> Enrollment:
    """Consume `token`, sign the CSR and register the device; commits on success."""
    row = db.scalars(
        select(EnrollmentToken).where(EnrollmentToken.token_sha256 == token_sha256(token))
    ).first()
    if row is None:
        raise EnrollmentError(401, "invalid enrollment token")
    now = clock.now()
    if row.used_at is not None or row.expires_at <= now:
        raise EnrollmentError(410, "enrollment token already used or expired")

    device_id = uuid.uuid4()
    try:
        cert = ca.sign_csr(csr_pem.encode("utf-8"), device_id)
    except ValueError as exc:  # CAError and non-ASCII PEM alike
        raise EnrollmentError(400, f"CSR rejected: {exc}") from exc
    fingerprint = cert_fingerprint(cert)

    db.add(
        Device(
            id=device_id,
            name=device_name,
            owner_user_id=row.created_by,
            cert_fingerprint=fingerprint,
            cert_not_after=cert.not_valid_after_utc,
            created_at=now,
        )
    )
    db.flush()
    # Guarded single-use claim: a concurrent enrollment with the same token gets 0 rows.
    claimed = db.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.id == row.id,
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
        .values(used_at=now, device_id=device_id)
        .execution_options(synchronize_session=False)
    )
    if int(getattr(claimed, "rowcount", 0)) != 1:
        db.rollback()
        raise EnrollmentError(410, "enrollment token already used or expired")
    audit.record(
        db,
        action="device.enroll",
        actor_user_id=None,
        actor_device_id=device_id,
        target=str(device_id),
        details={
            "device_name": device_name,
            "issued_by": str(row.created_by),
            "cert_fingerprint": fingerprint,
            "cert_not_after": cert.not_valid_after_utc.isoformat(),
        },
    )
    db.commit()
    return Enrollment(
        device_id=device_id,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_pem=ca.cert_pem.decode("ascii"),
    )

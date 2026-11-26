"""RFC 6238 TOTP (30 s, 6 digits, +/-1 step) and at-rest encryption of TOTP secrets."""

from __future__ import annotations

import base64
import hmac
import io
import re
from datetime import datetime

import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from audidash_server import clock

ISSUER = "SOC AudiDashboard"
STEP_SECONDS = 30
DIGITS = 6
VALID_WINDOW = 1
_CODE_RE = re.compile(r"^\d{6}$")


def _fernet(secret_key: str, info: bytes) -> Fernet:
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
        secret_key.encode("utf-8")
    )
    return Fernet(base64.urlsafe_b64encode(raw))


def totp_fernet(secret_key: str) -> Fernet:
    """Fernet keyed by HKDF-SHA256(secret_key, info=b"audidash-totp")."""
    return _fernet(secret_key, b"audidash-totp")


def setup_fernet(secret_key: str) -> Fernet:
    """Separate key for the short-lived TOTP enrolment token carried by the setup form."""
    return _fernet(secret_key, b"audidash-totp-setup")


def encrypt_totp_secret(secret: str, secret_key: str) -> str:
    return totp_fernet(secret_key).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(token: str, secret_key: str) -> str:
    """Raise ValueError if the token was not produced with this key (or was tampered with)."""
    try:
        return totp_fernet(secret_key).decrypt(token.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise ValueError("TOTP secret cannot be decrypted with the current secret key") from exc


def totp_secret_new() -> str:
    return pyotp.random_base32()  # 32 base32 chars = 160 bits


def _timestep(at: datetime) -> int:
    return int(at.timestamp()) // STEP_SECONDS


def totp_match_step(secret: str, code: str, at: datetime | None = None) -> int | None:
    """Return the matching time step within +/-1 step of `at`, or None."""
    code = code.strip().replace(" ", "")
    if not _CODE_RE.match(code):
        return None
    when = at or clock.now()
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS)
    current = _timestep(when)
    matched: int | None = None
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        expected = totp.generate_otp(step)
        # Check every candidate (no early exit) and compare in constant time.
        if hmac.compare_digest(expected.encode(), code.encode()):
            matched = step
    return matched


def totp_verify(secret: str, code: str, at: datetime | None = None) -> bool:
    return totp_match_step(secret, code, at) is not None


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_svg_data_uri(uri: str) -> str:
    """QR as an SVG `data:` URI for <img src>; CSP img-src allows data:, no inline styles."""
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, xmldecl=False)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

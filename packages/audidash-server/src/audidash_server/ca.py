"""Internal certificate authority that signs device client certificates (mTLS).

Root: EC P-256, 10-year validity, key stored encrypted (``BestAvailableEncryption``) under
``data_dir/ca/``. Device certificates: P-256 only, subject CN = device UUID, 90-day validity,
clientAuth EKU. The CSR only contributes its public key: its subject is ignored and any
requested extension is refused.
"""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import SecretStr

from audidash_server import clock

CA_VALIDITY = timedelta(days=3650)
DEVICE_CERT_VALIDITY = timedelta(days=90)
CA_COMMON_NAME = "SOC AudiDashboard Internal CA"
_CLOCK_SKEW = timedelta(minutes=5)


class CAError(ValueError):
    """CA files unusable, or a CSR that must not be signed. Messages never carry secrets."""


def cert_fingerprint(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 of the certificate DER (the format the proxy header carries)."""
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@dataclass(frozen=True)
class CA:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def fingerprint_sha256(self) -> str:
        return cert_fingerprint(self.cert)

    def sign_csr(self, csr_pem: bytes, device_id: uuid.UUID) -> x509.Certificate:
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise CAError("malformed CSR") from exc
        try:
            signature_ok = csr.is_signature_valid
            public_key = csr.public_key()
            requested = len(csr.extensions) + len(csr.attributes)
        except (ValueError, InvalidSignature) as exc:
            raise CAError("unsupported CSR") from exc
        if not signature_ok:
            raise CAError("CSR signature is invalid")
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise CAError("CSR key must be EC P-256")
        if requested:
            raise CAError("CSR must not request extensions or attributes")
        now = clock.now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(device_id))])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _CLOCK_SKEW)
            .not_valid_after(now + DEVICE_CERT_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
        )
        return builder.sign(self.key, hashes.SHA256())


def _key_usage(*, digital_signature: bool = False, cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _new_root() -> CA:
    key = ec.generate_private_key(ec.SECP256R1())
    now = clock.now()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + CA_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(cert_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return CA(key=key, cert=cert)


def _write_private(path: Path, data: bytes) -> None:
    """Create `path` exclusively with owner-only permissions (0600 on POSIX)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def load_or_create_ca(data_dir: Path, passphrase: SecretStr) -> CA:
    """Load the CA from ``data_dir/ca/``, creating it on first use."""
    secret = passphrase.get_secret_value().encode("utf-8")
    if not secret:
        raise CAError("CA passphrase is empty")
    ca_dir = data_dir / "ca"
    key_path, cert_path = ca_dir / "ca.key", ca_dir / "ca.crt"
    if not key_path.exists() and not cert_path.exists():
        ca_dir.mkdir(parents=True, exist_ok=True)
        ca = _new_root()
        encrypted = ca.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(secret),
        )
        _write_private(key_path, encrypted)
        cert_path.write_bytes(ca.cert_pem)
        return ca
    if not (key_path.is_file() and cert_path.is_file()):
        raise CAError(f"incomplete CA in {ca_dir}: need both ca.key and ca.crt")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=secret)
    except (ValueError, TypeError) as exc:
        raise CAError("cannot decrypt CA key (wrong AUDIDASH_CA_PASSPHRASE?)") from exc
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except ValueError as exc:
        raise CAError("CA certificate is malformed") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or (
        key.public_key().public_numbers() != cert.public_key().public_numbers()  # type: ignore[union-attr]
    ):
        raise CAError("CA key does not match CA certificate")
    return CA(key=key, cert=cert)

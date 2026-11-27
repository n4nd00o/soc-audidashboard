"""Device key, CSR and certificate checks. The private key is created and kept locally."""

from __future__ import annotations

import hashlib
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")
_SEPARATORS = re.compile(r"[:\s]")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def sanitize_device_name(name: str) -> str:
    cleaned = _UNSAFE_NAME.sub("_", name).strip()[:64]
    return cleaned or "device"


def build_csr(key: ec.EllipticCurvePrivateKey, device_name: str) -> bytes:
    """PEM CSR with only a sanitized CN: the server ignores it and refuses any extension."""
    cn = sanitize_device_name(device_name)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def cert_fingerprint(cert_pem: str | bytes) -> str:
    """Lowercase hex SHA-256 of the certificate DER."""
    data = cert_pem.encode("ascii") if isinstance(cert_pem, str) else cert_pem
    cert = x509.load_pem_x509_certificate(data)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


_SINGLE_CERT_PEM = re.compile(
    rb"\A\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*\Z"
)


def parse_single_ca_pem(data: bytes) -> x509.Certificate:
    """The one CA certificate in ``data``; ValueError for anything else.

    Exactly one PEM CERTIFICATE block with only whitespace around it, and a CA (basic
    constraints ``ca=True``). A bundle would let an appended certificate ride along a
    fingerprint check that only looks at the first block, so callers must trust and store
    the re-serialized certificate, never the raw bytes.
    """
    if not _SINGLE_CERT_PEM.fullmatch(data) or data.count(b"-----BEGIN") != 1:
        raise ValueError("expected exactly one PEM CA certificate and nothing else")
    try:
        cert = x509.load_pem_x509_certificate(data)
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except (ValueError, x509.ExtensionNotFound):
        raise ValueError("expected exactly one PEM CA certificate and nothing else") from None
    if not is_ca:
        raise ValueError("expected exactly one PEM CA certificate and nothing else")
    return cert


def canonical_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def normalize_fingerprint(raw: str) -> str | None:
    """Lowercase hex without ':'/whitespace; None unless exactly 64 hex characters."""
    value = _SEPARATORS.sub("", raw).lower()
    return value if _HEX64.fullmatch(value) else None


def _spki(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def check_issued_certificate(cert_pem: str, ca_pem: str, key: ec.EllipticCurvePrivateKey) -> None:
    """Raise ValueError unless `cert_pem` is for our key and directly issued by `ca_pem`."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        ca = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
        cert_key = cert.public_key()
        if not isinstance(cert_key, ec.EllipticCurvePublicKey) or _spki(cert_key) != _spki(
            key.public_key()
        ):
            raise ValueError("certificate does not match the device key")
        cert.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ValueError("server returned an invalid certificate") from exc

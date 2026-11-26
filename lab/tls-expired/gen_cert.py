"""Build-time helper: write an EXPIRED self-signed certificate for the tls-expired lab target.

Usage: python gen_cert.py OUT_DIR   (writes OUT_DIR/lab.crt and OUT_DIR/lab.key)
The key is throwaway demo material generated inside the image build; it is never committed.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime(2020, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2020, 1, 2, tzinfo=UTC)


def main(out_dir: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "lab.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out_dir / "lab.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))

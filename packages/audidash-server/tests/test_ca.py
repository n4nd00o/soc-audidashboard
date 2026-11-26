import hashlib
import os
import stat
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from audidash_server.ca import CAError, load_or_create_ca
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import SecretStr

PASS = SecretStr("c" * 40)


def test_ca_created_encrypted_and_reloaded(tmp_path: Path) -> None:
    ca = load_or_create_ca(tmp_path, PASS)
    key_file = tmp_path / "ca" / "ca.key"
    assert key_file.is_file() and (tmp_path / "ca" / "ca.crt").is_file()
    assert b"ENCRYPTED PRIVATE KEY" in key_file.read_bytes()
    again = load_or_create_ca(tmp_path, PASS)
    assert again.fingerprint_sha256() == ca.fingerprint_sha256()
    assert again.cert_pem == ca.cert_pem


def test_ca_root_properties(tmp_path: Path, frozen_clock: Any) -> None:
    ca = load_or_create_ca(tmp_path, PASS)
    cert = x509.load_pem_x509_certificate(ca.cert_pem)
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"  # type: ignore[union-attr]
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca
    validity = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert timedelta(days=3650) <= validity <= timedelta(days=3653)
    der = cert.public_bytes(serialization.Encoding.DER)
    assert ca.fingerprint_sha256() == hashlib.sha256(der).hexdigest()


def test_ca_wrong_passphrase_fails(tmp_path: Path) -> None:
    load_or_create_ca(tmp_path, PASS)
    with pytest.raises(CAError):
        load_or_create_ca(tmp_path, SecretStr("w" * 40))


def test_ca_empty_passphrase_refused(tmp_path: Path) -> None:
    with pytest.raises(CAError):
        load_or_create_ca(tmp_path, SecretStr(""))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_ca_key_is_owner_only(tmp_path: Path) -> None:
    load_or_create_ca(tmp_path, PASS)
    mode = stat.S_IMODE(os.stat(tmp_path / "ca" / "ca.key").st_mode)
    assert mode == 0o600


def test_sign_csr_sets_cn_eku_and_validity(tmp_path: Path, frozen_clock: Any, csr: Any) -> None:
    ca = load_or_create_ca(tmp_path, PASS)
    device_id = uuid.uuid4()
    cert = ca.sign_csr(csr(), device_id)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [a.value for a in cn] == [str(device_id)]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert cert.not_valid_before_utc <= frozen_clock.current
    assert cert.not_valid_after_utc == frozen_clock.current.replace(microsecond=0) + timedelta(
        days=90
    )
    cert.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.cert_pem))


@pytest.mark.parametrize(
    "key",
    [
        ec.generate_private_key(ec.SECP384R1()),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    ],
    ids=["p384", "rsa"],
)
def test_sign_csr_rejects_non_p256(tmp_path: Path, key: object) -> None:
    from cryptography.hazmat.primitives import hashes

    ca = load_or_create_ca(tmp_path, PASS)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())  # type: ignore[arg-type]
        .public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(CAError):
        ca.sign_csr(csr, uuid.uuid4())


def test_sign_csr_rejects_extensions(tmp_path: Path, csr: Any) -> None:
    ca = load_or_create_ca(tmp_path, PASS)
    with pytest.raises(CAError):
        ca.sign_csr(csr(san="evil.example"), uuid.uuid4())


def test_sign_csr_rejects_garbage(tmp_path: Path) -> None:
    ca = load_or_create_ca(tmp_path, PASS)
    with pytest.raises(CAError):
        ca.sign_csr(b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n", uuid.uuid4())

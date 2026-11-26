"""Internal certificate authority that signs device client certificates (mTLS).

Root: EC P-256, 10-year validity, key stored encrypted (``BestAvailableEncryption``) under
``data_dir/ca/``. Device certificates: P-256 only, subject CN = device UUID, 90-day validity,
clientAuth EKU. The CSR only contributes its public key: its subject is ignored and any
requested extension is refused.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import os
import re
import sys
import time
import uuid
from collections.abc import Iterator
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
SERVER_CERT_DEFAULT_DAYS = 397
SERVER_CERT_MAX_DAYS = 398
_LOCK_WAIT_SECONDS = 20.0
_LOCK_STALE_SECONDS = 30.0


_LDH_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DNS_NAME = re.compile(rf"(?=.{{1,253}}$){_LDH_LABEL}(?:\.{_LDH_LABEL})*")


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

    def issue_server_cert(
        self, hosts: list[str], days: int = SERVER_CERT_DEFAULT_DAYS
    ) -> tuple[bytes, bytes]:
        """New P-256 TLS server certificate for `hosts` (DNS names or IPs); (cert_pem, key_pem).

        The unencrypted key is for the reverse proxy; the caller must store it 0600.
        """
        names, sans = _parse_hosts(hosts)
        if not 1 <= days <= SERVER_CERT_MAX_DAYS:
            raise CAError(f"days must be between 1 and {SERVER_CERT_MAX_DAYS}")
        key = ec.generate_private_key(ec.SECP256R1())
        now = clock.now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _CLOCK_SKEW)
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return cert.public_bytes(serialization.Encoding.PEM), key_pem


def _parse_hosts(hosts: list[str]) -> tuple[list[str], list[x509.GeneralName]]:
    """Validated host names (brackets stripped) and their SAN entries (IP or DNS)."""
    names = [h.strip().removeprefix("[").removesuffix("]") for h in hosts if h.strip()]
    if not names:
        raise CAError("at least one host is required")
    sans: list[x509.GeneralName] = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            if not _DNS_NAME.fullmatch(name) or name.rsplit(".", 1)[-1].isdigit():
                raise CAError(f"invalid host name: {name!r}") from None
            sans.append(x509.DNSName(name))
    return names, sans


def _san_key(name: x509.GeneralName) -> str:
    if isinstance(name, x509.IPAddress):
        return f"ip:{name.value}"
    if isinstance(name, x509.DNSName):
        return f"dns:{name.value.lower()}"
    return f"other:{name!r}"


def server_cert_problem(
    cert_pem: bytes, ca_cert: x509.Certificate, hosts: list[str], min_days: int
) -> str | None:
    """Why the proxy's server certificate must be reissued, or None if it is still good.

    Checks: signed by `ca_cert`, currently valid for at least `min_days` more days, and a
    SAN set equal to `hosts` (DNS names compared case-insensitively).
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError:
        return "certificado ilegível"
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        return "certificado não foi emitido pela CA atual"
    now = clock.now()
    if cert.not_valid_before_utc > now:
        return "certificado ainda não é válido"
    if cert.not_valid_after_utc - now < timedelta(days=min_days):
        return f"certificado expira em menos de {min_days} dias"
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return "certificado sem SAN"
    _, wanted = _parse_hosts(hosts)
    if {_san_key(n) for n in san} != {_san_key(n) for n in wanted}:
        return "SAN do certificado difere de AUDIDASH_API_HOSTS"
    return None


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
    """Create `path` exclusively with owner-only permissions (0600 on POSIX), fsynced."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def _fsync_dir(path: Path) -> None:
    if sys.platform == "win32":  # directories cannot be opened for fsync there
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_ca_files(ca_dir: Path, key_path: Path, cert_path: Path, secret: bytes) -> CA:
    """Write key then cert via same-directory temp files + os.replace; cert is published last.

    A crash therefore leaves either nothing or a key without a certificate (never trusted by
    anyone), never a certificate without its key.
    """
    ca = _new_root()
    encrypted = ca.key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(secret),
    )
    suffix = f".{os.getpid()}.{uuid.uuid4().hex}.tmp"
    key_tmp, cert_tmp = ca_dir / f"ca.key{suffix}", ca_dir / f"ca.crt{suffix}"
    try:
        _write_private(key_tmp, encrypted)
        _write_private(cert_tmp, ca.cert_pem)
        os.replace(key_tmp, key_path)
        os.replace(cert_tmp, cert_path)
        _fsync_dir(ca_dir)
    finally:
        for tmp in (key_tmp, cert_tmp):
            tmp.unlink(missing_ok=True)
    return ca


@contextlib.contextmanager
def _creation_lock(ca_dir: Path) -> Iterator[None]:
    """Cross-process exclusive section (O_EXCL lock file; a stale one is broken after 30 s)."""
    lock = ca_dir / "ca.create.lock"
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            os.close(os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > _LOCK_STALE_SECONDS:
                    lock.unlink(missing_ok=True)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() > deadline:
                raise CAError(f"timed out waiting for CA creation lock {lock}") from None
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def _paths(data_dir: Path) -> tuple[Path, Path, Path]:
    ca_dir = data_dir / "ca"
    return ca_dir, ca_dir / "ca.key", ca_dir / "ca.crt"


def _secret(passphrase: SecretStr) -> bytes:
    secret = passphrase.get_secret_value().encode("utf-8")
    if not secret:
        raise CAError("CA passphrase is empty")
    return secret


_ORPHAN_MESSAGE = (
    "incomplete CA: ca.key present without ca.crt — restore ca.crt from backup, "
    "or run `audidash-server init-ca --force` to start a new CA"
)


def load_or_create_ca(data_dir: Path, passphrase: SecretStr) -> CA:
    """Load the CA from ``data_dir/ca/``, creating it (atomically, multi-process safe) once.

    An existing ``ca.key`` is never overwritten: a key without its certificate is an error.
    """
    secret = _secret(passphrase)
    ca_dir, key_path, cert_path = _paths(data_dir)
    if not cert_path.exists():
        ca_dir.mkdir(parents=True, exist_ok=True)
        with _creation_lock(ca_dir):
            # Re-check under the lock: a concurrent creator may have finished meanwhile.
            if not cert_path.exists():
                if key_path.exists():
                    raise CAError(_ORPHAN_MESSAGE)
                return _create_ca_files(ca_dir, key_path, cert_path, secret)
    return _load_ca_files(key_path, cert_path, ca_dir, secret)


def load_existing_ca(data_dir: Path, passphrase: SecretStr) -> CA | None:
    """Load the CA without creating it; ``None`` when no CA files exist at all."""
    secret = _secret(passphrase)
    ca_dir, key_path, cert_path = _paths(data_dir)
    if not cert_path.exists():
        if key_path.exists():
            raise CAError(_ORPHAN_MESSAGE)
        return None
    return _load_ca_files(key_path, cert_path, ca_dir, secret)


def replace_ca(data_dir: Path, passphrase: SecretStr) -> tuple[CA, list[Path]]:
    """Start a new CA, renaming any existing files to ``*.orphan-<UTC stamp>`` (never deleted)."""
    secret = _secret(passphrase)
    ca_dir, key_path, cert_path = _paths(data_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    stamp = clock.now().strftime("%Y%m%dT%H%M%SZ")
    moved: list[Path] = []
    with _creation_lock(ca_dir):
        for path in (key_path, cert_path):
            if path.exists():
                target = path.with_name(f"{path.name}.orphan-{stamp}")
                os.replace(path, target)
                moved.append(target)
        return _create_ca_files(ca_dir, key_path, cert_path, secret), moved


def _load_ca_files(key_path: Path, cert_path: Path, ca_dir: Path, secret: bytes) -> CA:
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

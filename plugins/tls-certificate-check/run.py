"""Checks a server's TLS certificate (expiry, trust, hostname) and legacy protocol support.

Approach, stdlib only and without temporary files:
1. An unverified handshake fetches the certificate in DER form; its validity dates are read with
   a minimal ASN.1 parser (``ssl`` only decodes dates of certificates that already validated).
2. A normal verifying handshake classifies the failure through ``verify_code``: an untrusted or
   self-signed chain, or a hostname mismatch.
3. If the chain is untrusted, a second handshake trusts the presented certificate itself
   (``cadata``), so that only the host name check can still fail.
4. TLS 1.0 and 1.1 are probed with handshakes pinned to exactly that version.
"""

import socket
import ssl
import warnings
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from audidash_sdk import Reporter, run

REFERENCES = ["ISO27002:2022 8.24"]
TIMEOUT_S = 5.0
VERIFY_UNTRUSTED = {18, 19, 20, 21}  # self-signed / unknown issuer
VERIFY_MISMATCH = {62, 64}  # host name / IP address mismatch
TIME_TAGS = {0x17, 0x18}  # UTCTime, GeneralizedTime


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at ``pos``."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("truncated DER data")
    return tag, pos, pos + length


def _parse_time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii")
    if tag == 0x17:
        year = int(text[:2])
        text = ("19" if year >= 50 else "20") + text
    return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def cert_validity(der: bytes) -> tuple[datetime, datetime]:
    """(notBefore, notAfter) of a DER X.509 certificate."""
    _, start, _ = _tlv(der, 0)  # Certificate SEQUENCE
    _, pos, _ = _tlv(der, start)  # tbsCertificate SEQUENCE
    tag, _, end = _tlv(der, pos)
    if tag == 0xA0:  # optional explicit version
        pos = end
    for _ in range(3):  # serialNumber, signature, issuer; validity follows
        _, _, end = _tlv(der, pos)
        pos = end
    tag, vstart, _ = _tlv(der, pos)  # validity SEQUENCE
    times: list[datetime] = []
    pos = vstart
    for _ in range(2):
        tag, cstart, cend = _tlv(der, pos)
        if tag not in TIME_TAGS:
            raise ValueError("unexpected validity encoding")
        times.append(_parse_time(tag, der[cstart:cend]))
        pos = cend
    return times[0], times[1]


def _handshake(host: str, port: int, context: ssl.SSLContext) -> bytes:
    with (
        socket.create_connection((host, port), timeout=TIMEOUT_S) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        return tls.getpeercert(binary_form=True) or b""


def _lenient(context: ssl.SSLContext) -> ssl.SSLContext:
    """Allow old protocol versions so legacy servers can still be inspected."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.set_ciphers("ALL:@SECLEVEL=0")
            context.minimum_version = ssl.TLSVersion.TLSv1
    except (ssl.SSLError, ValueError):
        pass
    return context


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return _lenient(context)


def _verify_code(host: str, port: int, context: ssl.SSLContext) -> int | None:
    try:
        _handshake(host, port, context)
    except ssl.SSLCertVerificationError as exc:
        return int(exc.verify_code)
    except (ssl.SSLError, OSError):
        return None
    return 0


def accepts_legacy(host: str, port: int, version_name: str) -> bool:
    context = _unverified_context()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            version = getattr(ssl.TLSVersion, version_name)
            context.set_ciphers("ALL:@SECLEVEL=0")
            context.minimum_version = version
            context.maximum_version = version
        _handshake(host, port, context)
    except (ssl.SSLError, OSError, ValueError):
        return False
    return True


def parse_target(target: str) -> str:
    return (urlparse(target).hostname or "") if "://" in target else target.strip()


def main(data: dict[str, Any], report: Reporter) -> None:
    port = (data.get("parameters") or {}).get("port", 443)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        report.warn("Invalid parameter 'port': expected an integer from 1 to 65535.")
        return
    host = parse_target(str(data["target"]))
    if not host:
        report.warn("Target has no host name.")
        return
    try:
        der = _handshake(host, port, _unverified_context())
        not_before, not_after = cert_validity(der)
    except (ssl.SSLError, OSError, ValueError, IndexError) as exc:
        report.warn(f"Could not read a TLS certificate from {host}:{port}: {exc}")
        return

    where = f"{host}:{port}"
    seconds_left = (not_after - datetime.now(UTC)).total_seconds()
    days_left = int(seconds_left // 86400)
    if seconds_left < 0:
        report.add(
            id="TLS-EXPIRED",
            title="TLS certificate has expired",
            severity="critical",
            category="misconfiguration",
            evidence=f"The certificate of {where} expired on {not_after:%Y-%m-%d}.",
            recommendation="Renew and deploy a new certificate immediately.",
            references=REFERENCES,
        )
    elif days_left <= 30:
        report.add(
            id="TLS-EXPIRING",
            title=f"TLS certificate expires in {days_left} days",
            severity="high" if days_left <= 14 else "medium",
            category="misconfiguration",
            evidence=f"The certificate of {where} expires on {not_after:%Y-%m-%d}.",
            recommendation="Renew the certificate and automate renewal.",
            references=REFERENCES,
        )

    code = _verify_code(host, port, _lenient(ssl.create_default_context()))
    mismatch = code in VERIFY_MISMATCH
    if code in VERIFY_UNTRUSTED:
        report.add(
            id="TLS-SELF-SIGNED",
            title="TLS certificate is self-signed or not issued by a trusted CA",
            severity="medium",
            category="misconfiguration",
            evidence=f"The certificate of {where} does not chain to a trusted root.",
            recommendation="Use a certificate issued by a trusted certificate authority.",
            references=REFERENCES,
        )
        pinned = _lenient(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
        pinned.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
        mismatch = _verify_code(host, port, pinned) in VERIFY_MISMATCH
    if mismatch:
        report.add(
            id="TLS-HOSTNAME-MISMATCH",
            title="TLS certificate does not match the host name",
            severity="high",
            category="misconfiguration",
            evidence=f"The certificate of {where} is not valid for the name {host!r}.",
            recommendation="Issue a certificate whose names include the host clients connect to.",
            references=REFERENCES,
        )

    legacy = (("TLSv1", "1.0"), ("TLSv1_1", "1.1"))
    accepted = [label for name, label in legacy if accepts_legacy(host, port, name)]
    if accepted:
        report.add(
            id="TLS-WEAK-PROTOCOL",
            title="Server accepts deprecated TLS versions",
            severity="high",
            category="vulnerability",
            evidence=f"{where} completed a handshake using TLS {' and '.join(accepted)}.",
            recommendation="Disable TLS 1.0 and 1.1; allow TLS 1.2 or newer only.",
            references=REFERENCES,
        )


if __name__ == "__main__":
    run(main)

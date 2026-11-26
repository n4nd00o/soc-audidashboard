"""Trust boundary with the TLS-terminating reverse proxy (Caddy).

The proxy proves itself with a shared secret header and forwards the client certificate's
SHA-256 fingerprint. Without a valid secret, every proxy-supplied header is ignored.
"""

from __future__ import annotations

import hmac
import re

from fastapi import Request

from audidash_server.settings import Settings

PROXY_SECRET_HEADER = "X-Audidash-Proxy-Secret"  # noqa: S105 - header name, not a secret  # nosec B105
CLIENT_CERT_HEADER = "X-Client-Cert-Fingerprint"
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_SEPARATORS = re.compile(r"[:\s]")


def proxy_secret_valid(request: Request) -> bool:
    """True if the request carries the configured proxy secret (constant-time compare)."""
    settings: Settings = request.app.state.settings
    expected = settings.proxy_secret.get_secret_value()
    supplied = request.headers.get(PROXY_SECRET_HEADER)
    if not expected or supplied is None:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def normalize_fingerprint(raw: str | None) -> str | None:
    """Lowercase hex without ':' or whitespace; None unless exactly 64 hex characters."""
    if raw is None:
        return None
    value = _SEPARATORS.sub("", raw).lower()
    return value if _FINGERPRINT.fullmatch(value) else None


def client_ip(request: Request) -> str | None:
    """Client address: first X-Forwarded-For entry only from the trusted proxy, else the peer."""
    if proxy_secret_valid(request):
        forwarded = request.headers.get("X-Forwarded-For", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first[:64]
    return request.client.host if request.client else None

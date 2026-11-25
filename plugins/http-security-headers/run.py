"""Checks the HTTP response headers of a URL for common security headers."""

import http.client
import re
import ssl
from typing import Any
from urllib.parse import urlparse

from audidash_sdk import Reporter, run

REFERENCES = ["OWASP ASVS 14.4", "ISO27002:2022 8.26"]
TIMEOUT_S = 10.0
VERSIONED_BANNER = re.compile(r"\d+\.\d+")


def fetch_headers(url: str) -> http.client.HTTPResponse:
    """GET ``url`` without following redirects; certificate problems are not this plugin's job."""
    parts = urlparse(url)
    host = parts.hostname or ""
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, parts.port, timeout=TIMEOUT_S, context=context)
    else:
        conn = http.client.HTTPConnection(host, parts.port, timeout=TIMEOUT_S)
    try:
        conn.request("GET", path, headers={"User-Agent": "SOC-AudiDashboard-header-check"})
        response = conn.getresponse()
        response.read(1024)
        return response
    finally:
        conn.close()


def main(data: dict[str, Any], report: Reporter) -> None:
    target = str(data["target"])
    url = str((data.get("parameters") or {}).get("url") or "") or target
    if "://" not in url:
        url = f"https://{url}"
    parts = urlparse(url)
    try:
        valid = parts.scheme in ("http", "https") and bool(parts.hostname) and parts.port != 0
    except ValueError:
        valid = False
    if not valid:
        report.warn(f"Invalid URL {url!r}: expected http:// or https:// with a host name.")
        return
    try:
        response = fetch_headers(url)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        report.warn(f"Could not fetch {url}: {exc}")
        return

    headers = {name.lower(): value for name, value in response.getheaders()}
    csp = headers.get("content-security-policy", "")

    def missing(
        id: str,  # noqa: A002
        title: str,
        severity: str,
        fix: str,
    ) -> None:
        report.add(
            id=id,
            title=title,
            severity=severity,
            category="misconfiguration",
            evidence=f"{url} answered HTTP {response.status} without this protection.",
            recommendation=fix,
            references=REFERENCES,
        )

    if parts.scheme == "https" and "strict-transport-security" not in headers:
        missing(
            "HTTP-NO-HSTS",
            "Missing Strict-Transport-Security header",
            "medium",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        )
    if not csp:
        missing(
            "HTTP-NO-CSP",
            "Missing Content-Security-Policy header",
            "medium",
            "Define a Content-Security-Policy that restricts script and frame sources.",
        )
    if "x-content-type-options" not in headers:
        missing(
            "HTTP-NO-XCTO",
            "Missing X-Content-Type-Options header",
            "low",
            "Send 'X-Content-Type-Options: nosniff'.",
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        missing(
            "HTTP-NO-FRAME-PROTECTION",
            "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
            "low",
            "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
        )
    if "referrer-policy" not in headers:
        missing(
            "HTTP-NO-REFERRER-POLICY",
            "Missing Referrer-Policy header",
            "low",
            "Send 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
        )
    banner = headers.get("server", "")
    if VERSIONED_BANNER.search(banner):
        report.add(
            id="HTTP-SERVER-BANNER",
            title="Server header discloses a version number",
            severity="info",
            category="misconfiguration",
            evidence=f"{url} sent 'Server: {banner}'.",
            recommendation="Remove the version from the Server header.",
            references=REFERENCES,
        )


if __name__ == "__main__":
    run(main)

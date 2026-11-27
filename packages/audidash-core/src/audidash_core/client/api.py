"""HTTP client for the AudiDashboard server.

Device calls use mTLS: the TLS context trusts ONLY the pinned ``ca.crt`` (no system roots) and
presents ``device.crt``/``device.key``. Tests (and nothing else) inject an httpx ``transport``.
"""

from __future__ import annotations

import re
import ssl
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from audidash_core.client import identity
from audidash_core.client.config import ClientConfig, ClientError, SessionExpiredError
from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality

TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class ApiError(ClientError):
    """The server refused a request or could not be reached."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class TokenGrant(BaseModel):
    model_config = ConfigDict(extra="ignore")

    access_token: str
    expires_at: datetime


class AssetInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    address: str | None
    asset_type: TargetType
    criticality: Criticality


class UploadSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    new: int
    updated: int
    auto_resolved: int
    asset_score: float


class EnrollResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    device_id: str
    cert_pem: str
    ca_pem: str


def build_ssl_context(config: ClientConfig) -> ssl.SSLContext:
    """Trust only the pinned CA; present the device certificate (mTLS)."""
    try:
        context = ssl.create_default_context(cafile=str(config.ca_path))
        context.load_cert_chain(str(config.cert_path), str(config.key_path))
    except (ssl.SSLError, OSError) as exc:
        raise ClientError(f"cannot load device identity from {config.directory}: {exc}") from None
    return context


def _detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        detail = None
    if isinstance(detail, str) and detail:
        return detail
    return f"HTTP {response.status_code}"


def _connection_error(exc: httpx.HTTPError, url: str) -> ApiError:
    host = urlsplit(url).netloc
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError):
            if "hostname" in (cause.verify_message or ""):
                return ApiError(
                    f"TLS verification failed for {host}: certificate not valid for this host"
                )
            return ApiError(f"TLS verification failed for {host}: not signed by the pinned CA")
        if isinstance(cause, ssl.SSLError):
            return ApiError(f"TLS error talking to {host}: {cause.reason or 'handshake failed'}")
        cause = cause.__cause__ or cause.__context__
    return ApiError(f"cannot reach {host}: {type(exc).__name__}")


def _call(client: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        return client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise _connection_error(exc, url) from None


MAX_CA_PEM_BYTES = 16 * 1024


def enroll_ssl_context(ca_pem: str) -> ssl.SSLContext:
    """Trust only the single CA in ``ca_pem`` (no system roots), with hostname checking.

    The context is built from the re-serialized certificate, never from the raw text, so an
    extra certificate smuggled into ``ca_pem`` can never become a trust anchor.
    """
    try:
        cert = identity.parse_single_ca_pem(ca_pem.encode("ascii"))
        context = ssl.create_default_context(cadata=identity.canonical_pem(cert))
    except (ssl.SSLError, ValueError) as exc:
        raise ApiError(f"unusable CA certificate: {exc}") from None
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def fetch_ca_pem(dashboard_url: str, *, transport: httpx.BaseTransport | None = None) -> str:
    """GET /ca.pem WITHOUT TLS verification: the CA certificate is public and not secret.

    Nothing secret is sent. The body is read as a stream and abandoned past
    ``MAX_CA_PEM_BYTES``; it must hold exactly one CA certificate, which is returned
    re-serialized (canonical PEM). The caller MUST compare its SHA-256 with an out-of-band
    fingerprint (or have the user confirm it) before trusting it.
    """
    url = dashboard_url.rstrip("/") + "/ca.pem"
    with httpx.Client(
        transport=transport,
        verify=False,  # noqa: S501  # nosec B501 - public, non-secret, checked by fingerprint
        timeout=TIMEOUT,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        try:
            with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise ApiError(
                        f"cannot download the CA certificate: HTTP {response.status_code}"
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_CA_PEM_BYTES:
                        raise ApiError("cannot download the CA certificate: response too large")
        except httpx.HTTPError as exc:
            raise _connection_error(exc, url) from None
    try:
        cert = identity.parse_single_ca_pem(bytes(body))
    except ValueError as exc:
        raise ApiError(f"the server did not return a valid CA certificate: {exc}") from None
    return identity.canonical_pem(cert)


def enroll_device(
    dashboard_url: str,
    *,
    token: str,
    device_name: str,
    csr_pem: str,
    ca_pem: str | None,
    transport: httpx.BaseTransport | None = None,
) -> EnrollResult:
    """POST /enroll on the dashboard listener (server-TLS only, no client certificate yet).

    With ``ca_pem`` the TLS connection is verified against that CA alone (hostname included),
    so the single-use token is only ever sent to a server holding a certificate of the
    already-checked CA. ``ca_pem=None`` is the explicit ``--insecure-first-contact`` path
    (unverified TLS); the caller then checks the returned CA before trusting anything.
    """
    body = {"token": token, "device_name": device_name, "csr_pem": csr_pem}
    verify: ssl.SSLContext | bool = enroll_ssl_context(ca_pem) if ca_pem is not None else False
    with httpx.Client(
        transport=transport,
        verify=verify,
        timeout=TIMEOUT,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = _call(client, "POST", dashboard_url.rstrip("/") + "/enroll", json=body)
    if response.status_code != 201:
        raise ApiError(f"enrolment refused: {_detail(response)}", response.status_code)
    try:
        return EnrollResult.model_validate(response.json())
    except (ValueError, ValidationError):
        raise ApiError("enrolment failed: malformed server response") from None


class ApiClient:
    """Authenticated mTLS client for the ``/api/v1`` endpoints."""

    def __init__(
        self,
        config: ClientConfig,
        transport: httpx.BaseTransport | None = None,
        *,
        access_token: str | None = None,
    ) -> None:
        self.config = config
        self.access_token = access_token
        self._http = httpx.Client(
            base_url=config.api_url,
            transport=transport,
            verify=build_ssl_context(config) if transport is None else True,
            timeout=TIMEOUT,
            trust_env=False,
            follow_redirects=False,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _request(self, method: str, path: str, *, auth: bool = True, **kwargs: Any) -> Any:
        headers: dict[str, str] = {}
        if auth:
            if not self.access_token:
                raise SessionExpiredError
            headers["Authorization"] = f"Bearer {self.access_token}"
        response = _call(self._http, method, path, headers=headers, **kwargs)
        if auth and response.status_code == 401:
            raise SessionExpiredError
        if response.status_code not in (200, 201):
            raise ApiError(_detail(response), response.status_code)
        try:
            return response.json()
        except ValueError:
            raise ApiError("malformed server response", response.status_code) from None

    def login(self, username: str, password: str, totp: str) -> TokenGrant:
        body = {"username": username, "password": password, "totp": totp}
        data = self._request("POST", "/api/v1/auth/token", auth=False, json=body)
        try:
            return TokenGrant.model_validate(data)
        except ValidationError:
            raise ApiError("malformed server response") from None

    def assets(self) -> list[AssetInfo]:
        data = self._request("GET", "/api/v1/assets")
        try:
            return [AssetInfo.model_validate(item) for item in data]
        except (ValidationError, TypeError):
            raise ApiError("malformed server response") from None

    def create_asset(
        self,
        *,
        name: str,
        address: str | None,
        asset_type: TargetType,
        criticality: Criticality,
        tags: list[str],
    ) -> AssetInfo:
        """POST /api/v1/assets; an existing name raises ApiError with status 409."""
        body = {
            "name": name,
            "address": address,
            "asset_type": asset_type.value,
            "criticality": criticality.value,
            "tags": tags,
        }
        data = self._request("POST", "/api/v1/assets", json=body)
        try:
            return AssetInfo.model_validate(data)
        except ValidationError:
            raise ApiError("malformed server response") from None

    def upload_run(self, run_id: str, asset: str, result: dict[str, Any]) -> UploadSummary:
        body = {"run_id": run_id, "asset": asset, "result": result}
        data = self._request("POST", "/api/v1/runs", json=body)
        try:
            return UploadSummary.model_validate(data)
        except ValidationError:
            raise ApiError("malformed server response") from None

    def verified(self) -> frozenset[str]:
        """Manifest hashes an admin verified (GET /api/v1/verified)."""
        data = self._request("GET", "/api/v1/verified")
        items = data.get("manifest_sha256") if isinstance(data, dict) else None
        if not isinstance(items, list) or not all(
            isinstance(i, str) and _SHA256_HEX.fullmatch(i) for i in items
        ):
            raise ApiError("malformed server response")
        return frozenset(items)

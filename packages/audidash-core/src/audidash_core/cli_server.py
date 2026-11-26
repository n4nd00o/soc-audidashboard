"""CLI handlers that talk to the AudiDashboard server: enroll, login, assets and run --upload."""

from __future__ import annotations

import argparse
import getpass
import hmac
import json
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from audidash_core.cli_format import clean_line, table
from audidash_core.client import config as client_config
from audidash_core.client import identity
from audidash_core.client.api import ApiClient, AssetInfo, enroll_device
from audidash_core.client.config import ClientConfig, ClientError
from audidash_core.runner import RunResult
from audidash_core.scoring import band

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

ENROLL_HELP = (
    "enrol this device: generate a key and CSR locally and exchange a single-use token for a "
    "client certificate. Trust model (TOFU): the CA is not known before the first contact, so "
    "pass the CA fingerprint printed by `audidash-server` via --ca-fingerprint (checked against "
    "the CA the server returns before anything is saved); without it you must opt in with "
    "--insecure-first-contact. An interceptor who steals the token can only enrol their own "
    "device; the private key never leaves this machine."
)


class ServerCliError(Exception):
    """A one-line failure; `usage` selects exit code 2 instead of 1."""

    def __init__(self, message: str, *, usage: bool = False) -> None:
        super().__init__(message)
        self.usage = usage


def make_transport(directory: Path) -> httpx.BaseTransport | None:
    """Test seam: production always uses real mTLS (None = httpx default transport)."""
    return None


def _say(message: str, *, stderr: bool = False) -> None:
    print(clean_line(message), file=sys.stderr if stderr else sys.stdout)


def _https_url(raw: str, option: str) -> str:
    parts = urlsplit(raw)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ServerCliError(f"{option} must be an https:// URL without credentials", usage=True)
    return raw.rstrip("/")


def _directory() -> Path:
    return client_config.default_config_dir()


def _load(directory: Path) -> ClientConfig:
    try:
        return client_config.load_config(directory)
    except ClientError as exc:
        raise ServerCliError(str(exc)) from None


def _authed_client(directory: Path) -> ApiClient:
    try:
        config = client_config.load_config(directory)
        token = client_config.load_token(directory)
        return ApiClient(config, make_transport(directory), access_token=token)
    except ClientError as exc:
        raise ServerCliError(str(exc)) from None


# ---------------------------------------------------------------- enroll


def cmd_enroll(args: argparse.Namespace) -> int:
    dashboard = _https_url(args.server, "--server")
    api = _https_url(args.api, "--api")
    if _CONTROL.search(args.name) or not args.name.strip() or len(args.name) > 128:
        raise ServerCliError("--name must be 1-128 printable characters", usage=True)
    expected: str | None = None
    if args.ca_fingerprint:
        expected = identity.normalize_fingerprint(args.ca_fingerprint)
        if expected is None:
            raise ServerCliError("--ca-fingerprint must be a SHA-256 hex digest", usage=True)
    elif not args.insecure_first_contact:
        raise ServerCliError(
            "pass --ca-fingerprint SHA256 (printed by the server) to verify the CA on first "
            "contact, or --insecure-first-contact to accept the risk",
            usage=True,
        )
    else:
        _say(
            "WARNING: --insecure-first-contact: the server's identity is not verified. "
            "Anyone intercepting this connection can read the single-use token and enrol "
            "their own device in your place. Compare the CA fingerprint below with the one "
            "the server administrator gave you.",
            stderr=True,
        )
    directory = _directory()
    if client_config.is_enrolled(directory) and not args.force:
        raise ServerCliError(
            f"this device is already enrolled ({directory}); use --force to replace the identity"
        )

    token = args.token or getpass.getpass("Enrolment token: ").strip()
    if not token:
        raise ServerCliError("an enrolment token is required", usage=True)
    key = identity.generate_key()
    try:
        result = enroll_device(
            dashboard,
            token=token,
            device_name=args.name,
            csr_pem=identity.build_csr(key, args.name).decode("ascii"),
            verify_tls=False,  # TOFU: the returned CA is checked below, before saving anything
            transport=make_transport(directory),
        )
        actual = identity.cert_fingerprint(result.ca_pem)
    except (ClientError, ValueError) as exc:
        raise ServerCliError(str(exc)) from None
    if expected is not None and not hmac.compare_digest(actual, expected):
        raise ServerCliError("CA fingerprint mismatch — possible interception")
    try:
        identity.check_issued_certificate(result.cert_pem, result.ca_pem, key)
    except ValueError as exc:
        raise ServerCliError(str(exc)) from None
    client_config.save_enrollment(
        directory,
        key_pem=identity.key_to_pem(key),
        cert_pem=result.cert_pem.encode("ascii"),
        ca_pem=result.ca_pem.encode("ascii"),
        dashboard_url=dashboard,
        api_url=api,
        device_id=result.device_id,
    )
    _say(f"Enrolled device {result.device_id} (CA sha256 {actual}).")
    _say(f"Identity saved in {directory}. Next: `audidash login`.")
    return 0


# ---------------------------------------------------------------- login / assets


def cmd_login(args: argparse.Namespace) -> int:
    directory = _directory()
    config = _load(directory)
    username = input("Username: ").strip()
    if not username:
        raise ServerCliError("username is required", usage=True)
    password = getpass.getpass("Password: ")
    totp = input("TOTP code: ").strip()
    try:
        with ApiClient(config, make_transport(directory)) as client:
            grant = client.login(username, password, totp)
        client_config.save_token(directory, grant.access_token, grant.expires_at)
    except ClientError as exc:
        raise ServerCliError(f"login failed: {exc}") from None
    _say(f"Logged in as {username}; session valid until {grant.expires_at.isoformat()}.")
    return 0


def _list_assets(directory: Path) -> list[AssetInfo]:
    try:
        with _authed_client(directory) as client:
            return client.assets()
    except ClientError as exc:
        raise ServerCliError(str(exc)) from None


def cmd_assets(args: argparse.Namespace) -> int:
    assets = _list_assets(_directory())
    rows = [[a.name, a.address or "-", a.asset_type.value, a.criticality.value] for a in assets]
    print(table(["NAME", "ADDRESS", "TYPE", "CRITICALITY"], rows))
    return 0


# ---------------------------------------------------------------- verified allowlist


def sync_verified() -> frozenset[str]:
    """Fetch the server's verified-manifest allowlist and cache it for later `run`s."""
    directory = _directory()
    try:
        with _authed_client(directory) as client:
            hashes = client.verified()
        client_config.save_verified(directory, hashes)
    except ClientError as exc:
        raise ServerCliError(str(exc)) from None
    return hashes


def cached_verified() -> frozenset[str]:
    """The allowlist from the last `plugins list --sync-verified` (empty when never synced)."""
    return client_config.load_verified(_directory())


# ---------------------------------------------------------------- run --upload


@dataclass(frozen=True)
class UploadPlan:
    directory: Path
    asset: AssetInfo
    target: str


def prepare_upload(args: argparse.Namespace) -> UploadPlan | None:
    """Validate --upload/--asset BEFORE running the plugin; None when not uploading."""
    if not args.upload:
        if args.asset:
            raise ServerCliError("--asset needs --upload", usage=True)
        return None
    if not args.asset:
        raise ServerCliError("--upload needs --asset NAME", usage=True)
    directory = _directory()
    assets = _list_assets(directory)
    asset = next((a for a in assets if a.name == args.asset), None)
    if asset is None:
        known = ", ".join(sorted(a.name for a in assets)) or "(none)"
        raise ServerCliError(f"unknown asset {args.asset!r}; known assets: {known}", usage=True)
    accepted = {asset.name, asset.address} - {None}
    if args.target not in accepted:
        raise ServerCliError(
            f"--target {args.target!r} does not match asset {asset.name!r} "
            f"(name or address {asset.address!r})",
            usage=True,
        )
    return UploadPlan(directory, asset, asset.address or args.target)


def upload_result(plan: UploadPlan, result: RunResult, *, json_mode: bool) -> int:
    """Upload a finished local run; local output has already been printed."""
    payload = json.loads(result.model_dump_json())
    try:
        with _authed_client(plan.directory) as client:
            summary = client.upload_run(str(uuid.uuid4()), plan.asset.name, payload)
    except (ClientError, ServerCliError) as exc:
        _say(f"error: upload failed: {exc}", stderr=True)
        return 1
    _say(
        f"Uploaded: {summary.new} new, {summary.updated} updated, "
        f"{summary.auto_resolved} auto-resolved — asset score {summary.asset_score:.1f} "
        f"({band(summary.asset_score).value})",
        stderr=json_mode,
    )
    return 0


# ---------------------------------------------------------------- parser wiring


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    enroll = sub.add_parser(
        "enroll", help="enrol this device with a server", description=ENROLL_HELP
    )
    enroll.add_argument("--server", required=True, help="dashboard URL, e.g. https://host:8443")
    enroll.add_argument("--api", required=True, help="mTLS API URL, e.g. https://host:9443")
    enroll.add_argument(
        "--token",
        help="single-use enrolment token; write --token=VALUE (tokens can start with '-'); "
        "omit to be prompted",
    )
    enroll.add_argument("--name", required=True, help="device name")
    enroll.add_argument("--ca-fingerprint", metavar="SHA256", help="expected CA SHA-256 (hex)")
    enroll.add_argument(
        "--insecure-first-contact",
        action="store_true",
        help="enrol without verifying the CA (trust on first use; risky)",
    )
    enroll.add_argument("--force", action="store_true", help="replace an existing identity")
    enroll.set_defaults(func=cmd_enroll)

    login = sub.add_parser("login", help="log in (username, password, TOTP) to get an API token")
    login.set_defaults(func=cmd_login)

    assets = sub.add_parser("assets", help="list the server's assets")
    assets.set_defaults(func=cmd_assets)


def add_upload_args(run: argparse.ArgumentParser) -> None:
    run.add_argument("--upload", action="store_true", help="upload the result to the server")
    run.add_argument("--asset", metavar="NAME", help="server asset the run belongs to")

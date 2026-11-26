"""Client side of the server API: enroll, login, assets and run --upload.

The CLI talks to the real server app in-process: an httpx transport forwards requests to the
FastAPI app and injects the headers Caddy would add after terminating mTLS (the fingerprint of
the device certificate the client enrolled with). The TLS pinning itself is tested separately
against a local ``ssl`` server.
"""

import datetime as dt
import getpass
import json
import ssl
import sys
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx
import pyotp
import pytest
from audidash_core import cli_server
from audidash_core.cli import main
from audidash_core.client import config as client_config
from audidash_core.client import identity
from audidash_core.client.api import ApiClient
from audidash_core.client.config import ClientConfig, ClientError
from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality
from audidash_server import clock
from audidash_server.app import create_app
from audidash_server.auth.passwords import hash_password
from audidash_server.auth.totp import encrypt_totp_secret, totp_secret_new
from audidash_server.ca import load_or_create_ca
from audidash_server.models import Asset, Role, Run, User
from audidash_server.services.enrollment import create_enrollment_token
from audidash_server.settings import Settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_cli import make_plugin

PASSWORD = "Corr3ct-Horse-Battery-Staple"  # noqa: S105 - test fixture value
NOW = dt.datetime(2026, 11, 25, 12, 0, 10, tzinfo=dt.UTC)
SERVER = "https://testserver"
API = "https://testserver"
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


class ProxyTransport(httpx.BaseTransport):
    """Forward to the server app, adding the headers Caddy sets after verifying mTLS."""

    def __init__(self, app_client: TestClient, secret: str, config_dir: Path) -> None:
        self.app_client = app_client
        self.secret = secret
        self.config_dir = config_dir
        self.fail_runs: tuple[int, str] | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self.fail_runs and request.url.path == "/api/v1/runs":
            status, detail = self.fail_runs
            return httpx.Response(status, json={"detail": detail}, request=request)
        headers = dict(request.headers)
        cert = self.config_dir / "device.crt"
        if cert.exists():
            headers["X-Audidash-Proxy-Secret"] = self.secret
            headers["X-Client-Cert-Fingerprint"] = identity.cert_fingerprint(cert.read_bytes())
        r = self.app_client.request(
            request.method, str(request.url), content=request.content, headers=headers
        )
        skip = {"content-encoding", "content-length", "transfer-encoding"}
        return httpx.Response(
            r.status_code,
            headers=[(k, v) for k, v in r.headers.items() if k.lower() not in skip],
            content=r.content,
            request=request,
        )


@dataclass
class Env:
    app_client: TestClient
    settings: Settings
    config_dir: Path
    transport: ProxyTransport
    user: str
    totp_secret: str

    def new_token(self) -> str:
        with self.app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            admin = s.scalars(select(User)).first()
            assert admin is not None
            token = create_enrollment_token(s, admin.id)
            s.commit()
        return token

    def ca_fingerprint(self) -> str:
        ca = load_or_create_ca(self.settings.data_dir, self.settings.ca_passphrase)
        return ca.fingerprint_sha256()

    def totp(self) -> str:
        return pyotp.TOTP(self.totp_secret).at(NOW)

    def add_asset(self, name: str = "srv1", address: str | None = "srv1.local") -> None:
        with self.app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            s.add(
                Asset(
                    name=name,
                    address=address,
                    asset_type=TargetType.linux,
                    criticality=Criticality.high,
                    tags=[],
                    created_at=NOW,
                )
            )
            s.commit()

    def runs(self) -> list[Run]:
        with self.app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            return list(s.scalars(select(Run)).all())

    def enroll_args(self, *extra: str, token: str | None = None) -> list[str]:
        return [
            "enroll",
            "--server",
            SERVER,
            "--api",
            API,
            "--token",
            token or self.new_token(),
            "--name",
            "my laptop",
            *extra,
        ]

    def enroll(self) -> None:
        assert main(self.enroll_args("--ca-fingerprint", self.ca_fingerprint())) == 0

    def login(self, monkeypatch: pytest.MonkeyPatch, code: str | None = None) -> int:
        monkeypatch.setattr("builtins.input", _inputs(self.user, code or self.totp()))
        monkeypatch.setattr(getpass, "getpass", lambda _prompt="": PASSWORD)
        return main(["login"])


def _inputs(*answers: str) -> Callable[[str], str]:
    queue = list(answers)

    def _answer(_prompt: str = "") -> str:
        return queue.pop(0)

    return _answer


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    settings = Settings(
        dev_mode=True,
        data_dir=(tmp_path / "data"),
        database_url=f"sqlite:///{(tmp_path / 'audidash.db').as_posix()}",
    )
    settings.data_dir.mkdir()
    app_client = TestClient(create_app(settings), base_url="https://testserver")
    secret = totp_secret_new()
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(
            User(
                id=uuid.uuid4(),
                username="alice",
                password_hash=hash_password(PASSWORD),
                totp_secret_enc=encrypt_totp_secret(secret, settings.secret_key.get_secret_value()),
                role=Role.admin,
                failed_logins=0,
                created_at=NOW,
            )
        )
        s.commit()
    config_dir = tmp_path / "cfg" / "audidash"
    transport = ProxyTransport(app_client, settings.proxy_secret.get_secret_value(), config_dir)
    monkeypatch.setattr(clock, "now", lambda: NOW)
    monkeypatch.setattr(client_config, "utcnow", lambda: NOW)
    monkeypatch.setattr(client_config, "default_config_dir", lambda: config_dir)
    monkeypatch.setattr(cli_server, "make_transport", lambda _directory: transport)
    return Env(app_client, settings, config_dir, transport, "alice", secret)


def _files(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.glob("*")) if directory.exists() else []


# ------------------------------------------------------------------ enroll


def test_enroll_writes_identity_files(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(env.enroll_args("--ca-fingerprint", env.ca_fingerprint())) == 0
    assert _files(env.config_dir) == ["ca.crt", "device.crt", "device.key", "server.json"]
    info = json.loads((env.config_dir / "server.json").read_text())
    assert info["dashboard_url"] == SERVER and info["api_url"] == API
    key = serialization.load_pem_private_key((env.config_dir / "device.key").read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    cert = x509.load_pem_x509_certificate((env.config_dir / "device.crt").read_bytes())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == info["device_id"]
    assert "Enrolled device" in capsys.readouterr().out


@posix_only
def test_enroll_permissions(env: Env) -> None:
    env.enroll()
    assert (env.config_dir.stat().st_mode & 0o777) == 0o700
    assert (env.config_dir / "device.key").stat().st_mode & 0o777 == 0o600


def test_enroll_ca_fingerprint_mismatch_writes_nothing(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(env.enroll_args("--ca-fingerprint", "ab" * 32)) == 1
    assert "CA fingerprint mismatch" in capsys.readouterr().err
    assert _files(env.config_dir) == []


def test_enroll_accepts_colon_separated_uppercase_fingerprint(env: Env) -> None:
    fp = env.ca_fingerprint().upper()
    pretty = ":".join(fp[i : i + 2] for i in range(0, 64, 2))
    assert main(env.enroll_args("--ca-fingerprint", pretty)) == 0


def test_enroll_requires_fingerprint_or_explicit_insecure_flag(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(env.enroll_args()) == 2
    assert "--ca-fingerprint" in capsys.readouterr().err
    assert _files(env.config_dir) == []


def test_enroll_insecure_first_contact_warns_loudly(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(env.enroll_args("--insecure-first-contact")) == 0
    err = capsys.readouterr().err
    assert "WARNING" in err and "not verified" in err


def test_enroll_rejects_malformed_fingerprint_and_plain_http(env: Env) -> None:
    assert main(env.enroll_args("--ca-fingerprint", "not-hex")) == 2
    args = env.enroll_args("--ca-fingerprint", "ab" * 32)
    args[args.index("--server") + 1] = "http://testserver"
    assert main(args) == 2


def test_enroll_unknown_and_reused_token(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    fp = env.ca_fingerprint()
    assert main(env.enroll_args("--ca-fingerprint", fp, token="nope")) == 1  # noqa: S106
    token = env.new_token()
    assert main(env.enroll_args("--ca-fingerprint", fp, token=token)) == 0
    assert main(env.enroll_args("--ca-fingerprint", fp, "--force", token=token)) == 1
    assert capsys.readouterr().err.count("enrol") >= 1


def test_enroll_does_not_overwrite_existing_identity(env: Env) -> None:
    env.enroll()
    key_before = (env.config_dir / "device.key").read_bytes()
    assert main(env.enroll_args("--ca-fingerprint", env.ca_fingerprint())) == 1
    assert (env.config_dir / "device.key").read_bytes() == key_before


# ------------------------------------------------------------------ login


def test_login_success(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.enroll()
    assert env.login(monkeypatch) == 0
    token = json.loads((env.config_dir / "token.json").read_text())
    assert token["access_token"] and token["expires_at"]
    code = env.totp()
    for path in env.config_dir.iterdir():
        content = path.read_bytes()
        assert PASSWORD.encode() not in content
        assert code.encode() not in content


@posix_only
def test_token_file_permissions(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.enroll()
    assert env.login(monkeypatch) == 0
    assert (env.config_dir / "token.json").stat().st_mode & 0o777 == 0o600


def test_login_wrong_totp_fails_without_token(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env.enroll()
    assert env.login(monkeypatch, code="000000") == 1
    assert "login failed" in capsys.readouterr().err
    assert not (env.config_dir / "token.json").exists()


def test_login_requires_enrolment(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["login"]) == 1
    assert "audidash enroll" in capsys.readouterr().err


# ------------------------------------------------------------------ assets


def test_assets_lists_server_assets(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env.add_asset()
    env.enroll()
    assert env.login(monkeypatch) == 0
    capsys.readouterr()
    assert main(["assets"]) == 0
    out = capsys.readouterr().out
    assert "srv1" in out and "srv1.local" in out and "linux" in out


def test_assets_without_login_says_login(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.enroll()
    assert main(["assets"]) == 1
    assert "run `audidash login`" in capsys.readouterr().err


def test_expired_token_asks_for_login(
    env: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env.enroll()
    assert env.login(monkeypatch) == 0
    later = NOW + dt.timedelta(minutes=16)
    monkeypatch.setattr(client_config, "utcnow", lambda: later)
    assert main(["assets"]) == 1
    assert "session expired — run `audidash login`" in capsys.readouterr().err


# ------------------------------------------------------------------ run --upload


@pytest.fixture
def plugins(tmp_path: Path) -> Path:
    directory = tmp_path / "plugins"
    directory.mkdir()
    make_plugin(directory)
    return directory


def _run(plugins: Path, *extra: str, target: str = "srv1.local") -> int:
    return main(
        ["run", "demo-plugin", "--plugins-dir", str(plugins), "--target", target, "--yes", *extra]
    )


@pytest.fixture
def ready(env: Env, monkeypatch: pytest.MonkeyPatch) -> Env:
    env.add_asset()
    env.enroll()
    assert env.login(monkeypatch) == 0
    return env


def test_run_upload_prints_summary_and_stores_run(
    ready: Env, plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    assert _run(plugins, "--upload", "--asset", "srv1") == 0
    out = capsys.readouterr().out
    assert "Uploaded: 2 new, 0 updated, 0 auto-resolved — asset score " in out
    assert len(ready.runs()) == 1


def test_run_upload_accepts_asset_name_as_target(ready: Env, plugins: Path) -> None:
    assert _run(plugins, "--upload", "--asset", "srv1", target="srv1") == 0
    assert len(ready.runs()) == 1


def test_run_upload_uses_asset_address_as_plugin_target(
    ready: Env, plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    assert _run(plugins, "--upload", "--asset", "srv1", "--json", target="srv1") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["target"] == "srv1.local"


def test_run_upload_target_must_match_asset(
    ready: Env, plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(plugins, "--upload", "--asset", "srv1", target="other.host") == 2
    assert "does not match asset" in capsys.readouterr().err
    assert ready.runs() == []


def test_run_upload_unknown_asset(
    ready: Env, plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(plugins, "--upload", "--asset", "ghost") == 2
    assert "unknown asset" in capsys.readouterr().err


def test_run_upload_requires_asset_and_asset_requires_upload(ready: Env, plugins: Path) -> None:
    assert _run(plugins, "--upload") == 2
    assert _run(plugins, "--asset", "srv1") == 2


def test_run_upload_expired_session_does_not_run_plugin(
    ready: Env,
    plugins: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(client_config, "utcnow", lambda: NOW + dt.timedelta(hours=1))
    capsys.readouterr()
    assert _run(plugins, "--upload", "--asset", "srv1") == 1
    captured = capsys.readouterr()
    assert "run `audidash login`" in captured.err
    assert "Plugin:" not in captured.out


def test_run_upload_failure_keeps_local_results(
    ready: Env, plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ready.transport.fail_runs = (409, "run_id belongs to another device")
    capsys.readouterr()
    assert _run(plugins, "--upload", "--asset", "srv1") == 1
    captured = capsys.readouterr()
    assert "Plugin: demo-plugin" in captured.out and "DEMO-1" in captured.out
    assert "run_id belongs to another device" in captured.err
    assert "Uploaded:" not in captured.out


def test_run_without_upload_is_unchanged(env: Env, plugins: Path) -> None:
    assert _run(plugins) == 0


# ------------------------------------------------------------------ TLS pinning


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _issue(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    *,
    server: bool,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    usage = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
    return key, builder.sign(ca_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        body = json.dumps([]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


@dataclass
class TlsFixture:
    port: int
    pinned_ca: x509.Certificate
    other_ca: x509.Certificate
    device_key: ec.EllipticCurvePrivateKey
    device_cert: x509.Certificate
    directory: Path

    def config(self, ca: x509.Certificate) -> ClientConfig:
        self.directory.mkdir(exist_ok=True)
        (self.directory / "device.key").write_bytes(_key_pem(self.device_key))
        (self.directory / "device.crt").write_bytes(_pem(self.device_cert))
        (self.directory / "ca.crt").write_bytes(_pem(ca))
        return ClientConfig(
            self.directory,
            f"https://localhost:{self.port}",
            f"https://localhost:{self.port}",
            "dev-1",
        )


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[TlsFixture]:
    pinned_key, pinned_cert = _make_ca("pinned CA")
    other_key, other_cert = _make_ca("other CA")
    server_key, server_cert = _issue(pinned_key, pinned_cert, "localhost", server=True)
    device_key, device_cert = _issue(pinned_key, pinned_cert, "device", server=False)
    cert_file, key_file, ca_file = (tmp_path / n for n in ("s.crt", "s.key", "ca.crt"))
    cert_file.write_bytes(_pem(server_cert))
    key_file.write_bytes(_key_pem(server_key))
    ca_file.write_bytes(_pem(pinned_cert))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.load_verify_locations(ca_file)
    context.verify_mode = ssl.CERT_REQUIRED  # mTLS: the client must present a device cert
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield TlsFixture(
            httpd.server_address[1],
            pinned_cert,
            other_cert,
            device_key,
            device_cert,
            tmp_path / "client",
        )
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_mtls_succeeds_against_pinned_ca(tls_server: TlsFixture) -> None:
    config = tls_server.config(tls_server.pinned_ca)
    assert ApiClient(config, access_token="t").assets() == []  # noqa: S106


def test_server_not_signed_by_pinned_ca_is_refused(tls_server: TlsFixture) -> None:
    config = tls_server.config(tls_server.other_ca)
    with pytest.raises(ClientError, match="pinned CA"):
        ApiClient(config, access_token="t").assets()  # noqa: S106


# ------------------------------------------------------------------ identity helpers


def test_csr_has_no_extensions_and_sanitized_subject() -> None:
    key = identity.generate_key()
    csr = x509.load_pem_x509_csr(identity.build_csr(key, "bad\nname;rm -rf /"))
    assert len(csr.extensions) == 0
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "bad_name_rm -rf _"
    assert identity.sanitize_device_name("\n") == "_"
    assert identity.sanitize_device_name("   ") == "device"

"""Local fixture servers for the plugin tests (everything binds to 127.0.0.1)."""

import datetime as dt
import ipaddress
import socket
import ssl
import threading
import warnings
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from audidash_core.manifest import TargetType
from audidash_core.runner import RunInput, RunResult, run_local
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PLUGINS_DIR = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"


RunPlugin = Callable[[str, str, TargetType, dict[str, object]], RunResult]


@pytest.fixture
def run_plugin() -> RunPlugin:
    """``run_plugin(plugin_id, target, target_type, parameters)`` through the real runner."""

    def call(
        plugin_id: str, target: str, target_type: TargetType, parameters: dict[str, object]
    ) -> RunResult:
        return run_local(
            PLUGINS_DIR / plugin_id,
            RunInput(target=target, target_type=target_type, parameters=parameters),
            timeout_s=60,
        )

    return call


@pytest.fixture
def free_port() -> int:
    """A TCP port on 127.0.0.1 that nothing listens on (connect is refused)."""
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class TcpListener:
    def __init__(self, port: int = 0) -> None:
        self._sock = socket.socket()
        try:
            self._sock.bind((HOST, port))
        except OSError:
            self._sock.close()
            raise
        self._sock.listen(16)
        self.port = int(self._sock.getsockname()[1])
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            conn.close()

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=5)


@pytest.fixture
def tcp_listener() -> Iterator[Callable[..., TcpListener]]:
    """Factory for plain TCP listeners; ``port=0`` picks an ephemeral port."""
    created: list[TcpListener] = []

    def make(port: int = 0) -> TcpListener:
        listener = TcpListener(port)
        created.append(listener)
        return listener

    yield make
    for listener in created:
        listener.close()


def make_cert(
    directory: Path,
    names: list[str],
    not_before: dt.datetime,
    not_after: dt.datetime,
    ca_signed: bool = False,
) -> tuple[Path, Path]:
    """Create a certificate (self-signed, or signed by a throwaway unknown CA).

    Returns (cert_path, key_path).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unknown Test CA")])
    sans: list[x509.GeneralName] = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_name if ca_signed else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(ca_key if ca_signed else key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Failed handshakes are expected in these tests; keep stderr clean."""


class Server:
    """Threaded HTTP(S) server answering every GET with configurable headers."""

    def __init__(
        self,
        headers: dict[str, str],
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        extra = dict(headers)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                for name, value in extra.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def version_string(self) -> str:
                return ""

        self._httpd = _QuietServer((HOST, 0), Handler)
        if tls_context is not None:
            self._httpd.socket = tls_context.wrap_socket(
                self._httpd.socket, server_side=True, do_handshake_on_connect=False
            )
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}/"

    @property
    def https_url(self) -> str:
        return f"https://{HOST}:{self.port}/"

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def http_server() -> Iterator[Callable[..., Server]]:
    """Factory: ``http_server({"X-Frame-Options": "DENY"})`` serves those headers over HTTP."""
    servers: list[Server] = []

    def make(headers: dict[str, str] | None = None) -> Server:
        server = Server(headers or {})
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def tls_server_context(cert: Path, key: Path, *, legacy: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    if legacy:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.set_ciphers("ALL:@SECLEVEL=0")
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1
    return context


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[Callable[..., Server]]:
    """Factory for HTTPS servers with a self-signed cert.

    ``tls_server(days_left=10)``; ``names`` sets the certificate SANs; ``legacy=True`` offers
    only TLS 1.0 (skips the test when the local OpenSSL cannot).
    """
    servers: list[Server] = []

    def make(
        days_left: float = 365,
        names: list[str] | None = None,
        headers: dict[str, str] | None = None,
        legacy: bool = False,
        ca_signed: bool = False,
    ) -> Server:
        now = dt.datetime.now(dt.UTC)
        directory = tmp_path / f"cert{len(servers)}"
        directory.mkdir()
        cert, key = make_cert(
            directory,
            names or ["localhost", HOST],
            not_before=now - dt.timedelta(days=400),
            not_after=now + dt.timedelta(days=days_left),
            ca_signed=ca_signed,
        )
        try:
            context = tls_server_context(cert, key, legacy=legacy)
        except (ssl.SSLError, ValueError) as exc:
            pytest.skip(f"local OpenSSL cannot offer TLS 1.0: {exc}")
        server = Server(headers or {}, context)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.fixture
def cert_factory() -> Callable[..., tuple[Path, Path]]:
    return make_cert

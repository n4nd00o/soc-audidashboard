"""Static checks of the deployment stack (compose, Caddyfile, Dockerfiles).

These run without a Docker daemon. The real build/up is exercised by the CI
``compose-smoke`` job.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

DEPLOY = Path(__file__).resolve().parents[1]
REPO = DEPLOY.parent
COMPOSE = DEPLOY / "docker-compose.yml"
CADDYFILE = DEPLOY / "Caddyfile"
DOCKERFILE = DEPLOY / "Dockerfile.server"
ENTRYPOINT = DEPLOY / "entrypoint.sh"
ENV_EXAMPLE = DEPLOY / ".env.example"

LAB_SERVICES = {"web-noheaders", "tls-expired", "redis-open"}
LAB_HOST_PORTS = {"web-noheaders": "18080", "tls-expired": "18443", "redis-open": "16379"}
SECRET_VARS = (
    "AUDIDASH_SECRET_KEY",
    "AUDIDASH_PROXY_SECRET",
    "AUDIDASH_CA_PASSPHRASE",
    "POSTGRES_PASSWORD",
)


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def services(compose: dict[str, Any]) -> dict[str, dict[str, Any]]:
    svc = compose["services"]
    assert isinstance(svc, dict)
    return svc


@pytest.fixture(scope="module")
def caddy_sites() -> dict[str, str]:
    """Map each ``...:PORT`` site block in the Caddyfile to its body text."""
    text = CADDYFILE.read_text(encoding="utf-8")
    sites: dict[str, str] = {}
    for match in re.finditer(r"^(\S*:(\d+))\s*\{\n(.*?)^\}", text, re.M | re.S):
        sites[match.group(2)] = match.group(3)
    return sites


def _ports(service: dict[str, Any]) -> list[str]:
    return [str(p) for p in service.get("ports", [])]


def test_expected_services(services: dict[str, dict[str, Any]]) -> None:
    assert {"db", "server", "proxy"} | LAB_SERVICES <= set(services)


def test_only_proxy_and_lab_publish_ports(services: dict[str, dict[str, Any]]) -> None:
    publishers = {name for name, svc in services.items() if svc.get("ports")}
    assert publishers == {"proxy"} | LAB_SERVICES
    for name in ("db", "server"):
        assert "ports" not in services[name]
        assert "network_mode" not in services[name]


def test_proxy_publishes_only_8443_and_9443(services: dict[str, dict[str, Any]]) -> None:
    targets = sorted(p.rsplit(":", 1)[-1] for p in _ports(services["proxy"]))
    assert targets == ["8443", "9443"]


def test_lab_ports_bound_to_loopback(services: dict[str, dict[str, Any]]) -> None:
    for name, host_port in LAB_HOST_PORTS.items():
        ports = _ports(services[name])
        assert len(ports) == 1, name
        assert ports[0].startswith(f"127.0.0.1:{host_port}:"), ports


def test_lab_services_only_on_lab_network(services: dict[str, dict[str, Any]]) -> None:
    for name in LAB_SERVICES:
        assert list(services[name]["networks"]) == ["lab"], name
    for name in ("db", "server", "proxy"):
        assert "lab" not in services[name]["networks"], name


def test_backend_network_is_internal(compose: dict[str, Any]) -> None:
    assert compose["networks"]["backend"].get("internal") is True
    assert compose["networks"]["lab"].get("internal") is not True


def test_server_waits_for_healthy_db(services: dict[str, dict[str, Any]]) -> None:
    assert services["server"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert services["proxy"]["depends_on"]["server"]["condition"] == "service_healthy"
    assert services["db"]["healthcheck"]["test"] == [
        "CMD",
        "pg_isready",
        "-h",
        "127.0.0.1",
        "-U",
        "audidash",
        "-d",
        "audidash",
    ]
    assert services["db"]["environment"]["POSTGRES_USER"] == "audidash"
    assert services["db"]["environment"]["POSTGRES_DB"] == "audidash"


def test_containers_hardened(services: dict[str, dict[str, Any]]) -> None:
    for name, svc in services.items():
        assert svc.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in svc.get("security_opt", []), name
        assert svc.get("read_only") is True, name


def test_non_root_users(services: dict[str, dict[str, Any]]) -> None:
    assert services["proxy"]["user"] == "10001:10001"
    assert services["redis-open"]["user"] == "redis"
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert users, "Dockerfile.server must switch to a non-root USER"
    assert users[-1] == "10001:10001"
    for lab in ("web-noheaders", "tls-expired"):
        lab_users = re.findall(
            r"^USER\s+(\S+)", (REPO / "lab" / lab / "Dockerfile").read_text("utf-8"), re.M
        )
        assert lab_users and lab_users[-1] not in {"root", "0", "0:0"}, lab


def test_secrets_come_from_env(services: dict[str, dict[str, Any]]) -> None:
    raw = COMPOSE.read_text(encoding="utf-8")
    for var in SECRET_VARS:
        assert f"${{{var}:?" in raw, f"{var} must be required from the environment"
    for svc in services.values():
        env = svc.get("environment", {})
        assert isinstance(env, dict)
        for key, value in env.items():
            if any(word in key for word in ("SECRET", "PASSWORD", "PASSPHRASE")):
                assert str(value).startswith("${"), f"literal secret in {key}"
            if key == "AUDIDASH_DATABASE_URL":
                assert "${POSTGRES_PASSWORD:?" in str(value)


def test_server_volumes_not_exposed_to_proxy(services: dict[str, dict[str, Any]]) -> None:
    proxy_vols = [str(v) for v in services["proxy"]["volumes"]]
    assert all(v.endswith(":ro") for v in proxy_vols), proxy_vols
    assert not any(v.startswith("server_data") for v in proxy_vols)
    assert any(v.startswith("proxy_shared:/shared") for v in proxy_vols)


def test_env_example_has_only_placeholders() -> None:
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in SECRET_VARS:
            assert value == "CHANGE_ME", key


def test_env_example_requires_url_safe_secrets() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "token_urlsafe" in text
    assert "URL-safe" in text
    readme = (DEPLOY / "README.md").read_text(encoding="utf-8")
    assert readme.count("URL-safe") >= 2  # PT-BR and EN sections


def test_env_example_is_not_ignored() -> None:
    text = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert "!deploy/.env.example" in text.splitlines()


def test_caddy_global_options() -> None:
    text = CADDYFILE.read_text(encoding="utf-8")
    head = text.split("}", 1)[0]
    assert re.search(r"^\s*admin off\s*$", head, re.M)
    assert "skip_install_trust" in head
    # IP-literal clients send no SNI; they still get the internal-CA certificate.
    assert re.search(r"^\s*default_sni localhost\s*$", head, re.M)


def test_caddy_strips_client_headers_on_both_listeners(caddy_sites: dict[str, str]) -> None:
    assert set(caddy_sites) == {"8443", "9443"}
    for port, body in caddy_sites.items():
        assert "request_header -X-Audidash-Proxy-Secret" in body, port
        assert "request_header -X-Client-Cert-Fingerprint" in body, port
        assert "header_up X-Audidash-Proxy-Secret {$AUDIDASH_PROXY_SECRET}" in body, port
        assert "header_up X-Forwarded-For {remote_host}" in body, port
        assert "reverse_proxy server:8000" in body, port


def test_caddy_dashboard_listener(caddy_sites: dict[str, str]) -> None:
    body = caddy_sites["8443"]
    # Issued by the AudiDashboard internal CA (verifiable by `audidash enroll`), not Caddy's.
    assert "tls /shared/dashboard.crt /shared/dashboard.key" in body
    assert "tls internal" not in CADDYFILE.read_text(encoding="utf-8")
    assert "client_auth" not in body
    assert "{http.request.tls.client.fingerprint}" not in body
    # Both the bare /api path and everything below it are blocked.
    assert re.search(r"@api path /api /api/\*", body)
    assert re.search(r"handle @api\s*\{\s*respond 404\s*\}", body)


def test_caddy_api_listener_requires_client_cert(caddy_sites: dict[str, str]) -> None:
    body = caddy_sites["9443"]
    assert "tls /shared/api.crt /shared/api.key" in body
    assert re.search(r"client_auth\s*\{[^}]*mode require_and_verify", body, re.S)
    assert "trust_pool file /shared/ca.crt" in body
    assert "header_up X-Client-Cert-Fingerprint {http.request.tls.client.fingerprint}" in body
    # Only /api/* is proxied; everything else is a 404.
    assert re.search(r"handle /api/\*\s*\{", body)
    assert re.search(r"handle\s*\{\s*respond 404\s*\}", body)


def test_dockerfile_server() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(r"^FROM ghcr\.io/astral-sh/uv:\d+\.\d+\.\d+ AS uv", text, re.M)
    assert re.search(r"^FROM python:3\.12\.\d+-slim AS ", text, re.M)
    assert "uv sync --frozen --no-dev --package audidash-server" in text
    assert "HEALTHCHECK" in text and "/healthz" in text
    assert "audidash_server.asgi:app_factory" in text
    assert '"--no-server-header"' in text
    assert '"--proxy-headers"' not in text


def test_entrypoint_is_strict_and_execs() -> None:
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "set -eu" in text
    assert "init-ca" in text and "issue-server-cert" in text
    assert re.search(r'^exec "\$@"$', text, re.M)
    # The API certificate is re-validated on every start, not only when absent.
    assert "check-server-cert" in text
    assert "--min-days 30" in text
    assert "\r" not in text
    # The dashboard listener gets an internal-CA certificate too, for AUDIDASH_DASHBOARD_HOSTS.
    assert 'DASHBOARD_HOSTS="${AUDIDASH_DASHBOARD_HOSTS:-localhost,127.0.0.1}"' in text
    assert 'ensure_server_cert dashboard "$DASHBOARD_HOSTS"' in text
    assert 'ensure_server_cert api "$API_HOSTS"' in text


def test_compose_passes_dashboard_hosts_to_the_server(services: dict[str, dict[str, Any]]) -> None:
    env = services["server"]["environment"]
    assert env["AUDIDASH_DASHBOARD_HOSTS"] == "${AUDIDASH_DASHBOARD_HOSTS:-localhost,127.0.0.1}"
    assert "AUDIDASH_DASHBOARD_HOST" not in services["proxy"]["environment"]
    assert "AUDIDASH_DASHBOARD_HOSTS" in ENV_EXAMPLE.read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX sh not available")
def test_entrypoint_issues_and_revalidates_both_listener_certs(tmp_path: Path) -> None:
    """Run the real entrypoint with a stub `audidash-server` that logs its arguments."""
    bin_dir, data = tmp_path / "bin", tmp_path / "data"
    bin_dir.mkdir()
    (data / "ca").mkdir(parents=True)
    (data / "ca" / "ca.crt").write_text("CA", encoding="utf-8")
    (data / "proxy").mkdir()
    (data / "proxy" / "api.key").write_text("k", encoding="utf-8")
    (data / "proxy" / "dashboard.key").write_text("k", encoding="utf-8")
    log = tmp_path / "calls.log"
    stub = (
        "#!/bin/sh\n"
        f'echo "$*" >> "{log.as_posix()}"\n'
        'case "$1" in check-server-cert) case "$*" in *dashboard*) exit 1;; esac;; esac\n'
        "exit 0\n"
    )
    for name in ("audidash-server", "python"):
        (bin_dir / name).write_text(stub, encoding="utf-8", newline="\n")
        (bin_dir / name).chmod(0o755)
    sh = shutil.which("sh")
    assert sh is not None
    result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [sh, ENTRYPOINT.as_posix(), "true"],
        env={
            "PATH": f"{bin_dir.as_posix()}:/usr/bin:/bin",
            "AUDIDASH_DATA_DIR": data.as_posix(),
            "AUDIDASH_DATABASE_URL": "sqlite://",
            "AUDIDASH_DASHBOARD_HOSTS": "dash.lan,10.0.0.5",
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    proxy = (data / "proxy").as_posix()
    # The current API certificate is kept; the stale dashboard one is reissued for its hosts.
    assert not any(c.startswith(f"issue-server-cert --out-cert {proxy}/api.crt") for c in calls)
    assert (
        f"issue-server-cert --out-cert {proxy}/dashboard.crt --out-key {proxy}/dashboard.key "
        "--host dash.lan --host 10.0.0.5"
    ) in calls
    assert (data / "proxy" / "ca.crt").read_text(encoding="utf-8") == "CA"


def test_ci_smoke_job_checks() -> None:
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    job = ci["jobs"]["compose-smoke"]
    script = "\n".join(step.get("run", "") for step in job["steps"])
    assert "--wait" in script
    assert "https://localhost:9443/api/v1/assets" in script
    assert "checkend 0" in script  # the lab certificate must really be expired
    # The dashboard listener is verified against the internal CA, never with curl -k.
    assert "--cacert" in script and "https://localhost:8443/healthz" in script
    assert "-fsSk" not in script and "-sk " not in script
    assert "openssl s_client -connect localhost:8443" in script
    assert "openssl s_client -connect 127.0.0.1:8443" in script  # no SNI: default_sni
    # Piped assertions break under `bash -eo pipefail` (SIGPIPE / non-zero producers).
    for line in script.splitlines():
        assert "| grep" not in line, line


def test_tls_expired_cert_window() -> None:
    text = (REPO / "lab" / "tls-expired" / "gen_cert.py").read_text(encoding="utf-8")
    assert "datetime(2020, 1, 1" in text and "datetime(2020, 1, 2" in text


def test_web_noheaders_config() -> None:
    conf = (REPO / "lab" / "web-noheaders" / "nginx.conf").read_text(encoding="utf-8")
    assert "server_tokens on;" in conf
    assert "add_header" not in conf


def test_redis_open_has_protected_mode_off(services: dict[str, dict[str, Any]]) -> None:
    command = services["redis-open"]["command"]
    assert "--protected-mode" in command
    assert command[command.index("--protected-mode") + 1] == "no"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_docker_compose_config_is_valid() -> None:
    docker = shutil.which("docker")
    assert docker is not None
    try:
        result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            [
                docker,
                "compose",
                "--env-file",
                str(ENV_EXAMPLE),
                "-f",
                str(COMPOSE),
                "config",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # Seen on GitHub's Windows runners: the docker CLI itself hangs. That says
        # nothing about the compose file, which the Linux jobs and compose-smoke check.
        pytest.skip("docker CLI did not respond within 60 s in this environment")
    if result.returncode != 0 and "unknown" in result.stderr and "compose" in result.stderr:
        pytest.skip("docker compose plugin not available")
    assert result.returncode == 0, result.stderr

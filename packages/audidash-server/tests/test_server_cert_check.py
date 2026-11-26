"""`audidash-server check-server-cert`: decides whether the proxy's API certificate is reusable."""

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from audidash_server import cli, clock
from audidash_server.ca import load_or_create_ca, server_cert_problem
from audidash_server.settings import Settings
from pydantic import SecretStr

PASSPHRASE = "p" * 32


@pytest.fixture
def ca_env(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("AUDIDASH_DEV_MODE", "1")
    monkeypatch.setenv("AUDIDASH_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("AUDIDASH_CA_PASSPHRASE", PASSPHRASE)
    return settings


def _write_cert(settings: Settings, path: Path, hosts: list[str], days: int = 90) -> None:
    ca = load_or_create_ca(settings.data_dir, SecretStr(PASSPHRASE))
    cert_pem, _ = ca.issue_server_cert(hosts, days)
    path.write_bytes(cert_pem)


def _check(path: Path, *hosts: str, min_days: int = 30) -> int:
    argv = ["check-server-cert", "--cert", str(path), "--min-days", str(min_days)]
    for host in hosts:
        argv += ["--host", host]
    return cli.main(argv)


def test_valid_cert_matching_hosts_is_reusable(ca_env: Settings, tmp_path: Path) -> None:
    cert = tmp_path / "api.crt"
    _write_cert(ca_env, cert, ["localhost", "127.0.0.1"])
    assert _check(cert, "127.0.0.1", "LOCALHOST") == 0


def test_san_mismatch_needs_reissue(ca_env: Settings, tmp_path: Path, capsys: Any) -> None:
    cert = tmp_path / "api.crt"
    _write_cert(ca_env, cert, ["localhost", "127.0.0.1"])
    assert _check(cert, "localhost") == 1
    assert _check(cert, "localhost", "127.0.0.1", "audi.example.org") == 1
    assert "SAN" in capsys.readouterr().err


def test_expiring_soon_needs_reissue(ca_env: Settings, tmp_path: Path, capsys: Any) -> None:
    cert = tmp_path / "api.crt"
    _write_cert(ca_env, cert, ["localhost"], days=20)
    assert _check(cert, "localhost", min_days=30) == 1
    assert "expira" in capsys.readouterr().err
    assert _check(cert, "localhost", min_days=10) == 0


def test_cert_from_another_ca_needs_reissue(ca_env: Settings, tmp_path: Path, capsys: Any) -> None:
    other = load_or_create_ca(tmp_path / "other", SecretStr(PASSPHRASE))
    cert_pem, _ = other.issue_server_cert(["localhost"], 90)
    cert = tmp_path / "api.crt"
    cert.write_bytes(cert_pem)
    load_or_create_ca(ca_env.data_dir, SecretStr(PASSPHRASE))
    assert _check(cert, "localhost") == 1
    assert "CA" in capsys.readouterr().err


def test_missing_or_garbage_cert_needs_reissue(ca_env: Settings, tmp_path: Path) -> None:
    load_or_create_ca(ca_env.data_dir, SecretStr(PASSPHRASE))
    assert _check(tmp_path / "absent.crt", "localhost") == 1
    garbage = tmp_path / "garbage.crt"
    garbage.write_bytes(b"not a certificate")
    assert _check(garbage, "localhost") == 1


def test_missing_ca_is_an_error(ca_env: Settings, tmp_path: Path, capsys: Any) -> None:
    assert _check(tmp_path / "api.crt", "localhost") == 2
    assert "init-ca" in capsys.readouterr().err


def test_server_cert_problem_not_yet_valid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))
    real_now = clock.now()
    monkeypatch.setattr(clock, "now", lambda: real_now + timedelta(days=1))
    cert_pem, _ = ca.issue_server_cert(["localhost"], 90)
    monkeypatch.setattr(clock, "now", lambda: real_now)
    problem = server_cert_problem(cert_pem, ca.cert, ["localhost"], 30)
    assert problem is not None and "ainda não" in problem

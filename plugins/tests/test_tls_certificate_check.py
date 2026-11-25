import datetime as dt
import importlib.util
import socket
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus

PLUGIN = "tls-certificate-check"
PLUGINS = Path(__file__).resolve().parent.parent


def _check(run_plugin: Any, port: object, host: str = "127.0.0.1") -> Any:
    return run_plugin(PLUGIN, host, TargetType.network, {"port": port})


def _ids(result: Any) -> set[str]:
    return {f.id for f in result.findings}


def test_expiring_in_10_days_is_high(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, tls_server(days_left=10).port)
    assert result.status is RunStatus.ok
    expiring = next(f for f in result.findings if f.id == "TLS-EXPIRING")
    assert expiring.severity.value == "high"
    assert "ISO27002:2022 8.24" in expiring.references


def test_expiring_in_25_days_is_medium(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, tls_server(days_left=25).port)
    expiring = next(f for f in result.findings if f.id == "TLS-EXPIRING")
    assert expiring.severity.value == "medium"


def test_valid_for_a_year_is_not_expiring(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    ids = _ids(_check(run_plugin, tls_server(days_left=365).port))
    assert "TLS-EXPIRING" not in ids
    assert "TLS-EXPIRED" not in ids


def test_expired_is_critical(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, tls_server(days_left=-5).port)
    expired = next(f for f in result.findings if f.id == "TLS-EXPIRED")
    assert expired.severity.value == "critical"
    assert "TLS-EXPIRING" not in _ids(result)


def test_self_signed_is_medium(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, tls_server().port)
    finding = next(f for f in result.findings if f.id == "TLS-SELF-SIGNED")
    assert finding.severity.value == "medium"
    assert "TLS-HOSTNAME-MISMATCH" not in _ids(result)


def test_hostname_mismatch_is_high(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, tls_server(names=["other.example"]).port)
    finding = next(f for f in result.findings if f.id == "TLS-HOSTNAME-MISMATCH")
    assert finding.severity.value == "high"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_weak_protocol_tls10(run_plugin: Any, tls_server: Callable[..., Any]) -> None:
    server = tls_server(legacy=True)
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe.check_hostname = False
    probe.verify_mode = ssl.CERT_NONE
    try:
        probe.set_ciphers("ALL:@SECLEVEL=0")
        probe.minimum_version = ssl.TLSVersion.TLSv1
        probe.maximum_version = ssl.TLSVersion.TLSv1
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=3) as raw,
            probe.wrap_socket(raw),
        ):
            pass
    except (ssl.SSLError, OSError, ValueError) as exc:
        pytest.skip(f"local OpenSSL cannot negotiate TLS 1.0 (client or server): {exc}")
    result = _check(run_plugin, server.port)
    finding = next(f for f in result.findings if f.id == "TLS-WEAK-PROTOCOL")
    assert finding.severity.value == "high"


def test_modern_server_has_no_weak_protocol(
    run_plugin: Any, tls_server: Callable[..., Any]
) -> None:
    assert "TLS-WEAK-PROTOCOL" not in _ids(_check(run_plugin, tls_server().port))


def test_unreachable_target_warns_once(run_plugin: Any, free_port: int) -> None:
    result = _check(run_plugin, free_port)
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1


def test_non_tls_service_warns_once(run_plugin: Any, tcp_listener: Callable[..., Any]) -> None:
    result = _check(run_plugin, tcp_listener().port)
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1


@pytest.mark.parametrize("port", [0, 70000, "443"])
def test_invalid_port_warns_once(run_plugin: Any, port: object) -> None:
    result = _check(run_plugin, port)
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1


def test_der_validity_parser_reads_utctime_and_generalizedtime(
    tmp_path: Path, cert_factory: Callable[..., Any]
) -> None:
    spec = importlib.util.spec_from_file_location("tls_run", PLUGINS / PLUGIN / "run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for year in (2031, 2051):  # UTCTime and GeneralizedTime
        not_after = dt.datetime(year, 3, 4, 5, 6, 7, tzinfo=dt.UTC)
        cert, _ = cert_factory(
            tmp_path, ["localhost"], dt.datetime(2020, 1, 2, tzinfo=dt.UTC), not_after
        )
        der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        before, after = module.cert_validity(der)
        assert before == dt.datetime(2020, 1, 2, tzinfo=dt.UTC)
        assert after == not_after

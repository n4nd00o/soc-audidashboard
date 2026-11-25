from collections.abc import Callable
from typing import Any

import pytest
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus

PLUGIN = "network-port-scan"


def _scan(run_plugin: Any, host: str, **params: object) -> Any:
    return run_plugin(PLUGIN, host, TargetType.network, params)


def test_open_port_reported_as_info(run_plugin: Any, tcp_listener: Callable[..., Any]) -> None:
    listener = tcp_listener()
    result = _scan(run_plugin, "127.0.0.1", ports=[listener.port], timeout_ms=2000)
    assert result.status is RunStatus.ok
    assert [(f.id, f.severity.value, f.item_key) for f in result.findings] == [
        ("NET-OPEN-PORT", "info", str(listener.port))
    ]
    assert result.warnings == []


def test_risky_port_reported_as_high(run_plugin: Any, tcp_listener: Callable[..., Any]) -> None:
    try:
        tcp_listener(6379)
    except OSError:
        pytest.skip("port 6379 is in use on this machine")
    result = _scan(run_plugin, "127.0.0.1", ports=[6379], timeout_ms=2000)
    by_id = {f.id: f for f in result.findings}
    assert by_id["NET-RISKY-PORT"].severity.value == "high"
    assert by_id["NET-RISKY-PORT"].item_key == "6379"
    assert "NET-OPEN-PORT" in by_id
    assert "CIS Control 4.4" in by_id["NET-RISKY-PORT"].references


def test_closed_port_gives_no_findings(run_plugin: Any, free_port: int) -> None:
    result = _scan(run_plugin, "127.0.0.1", ports=[free_port], timeout_ms=2000)
    assert result.status is RunStatus.ok
    assert result.findings == []


def test_unresolvable_target_warns_once(run_plugin: Any) -> None:
    result = _scan(run_plugin, "no-such-host.invalid", ports=[80], timeout_ms=500)
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1


@pytest.mark.parametrize(
    "params",
    [{"ports": [70000]}, {"ports": [0]}, {"ports": ["x"]}, {"ports": "80"}, {"timeout_ms": 0}],
)
def test_invalid_parameters_warn_once(run_plugin: Any, params: dict[str, object]) -> None:
    result = _scan(run_plugin, "127.0.0.1", **params)
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1


def test_default_port_list_is_used_without_ports(run_plugin: Any) -> None:
    result = _scan(run_plugin, "127.0.0.1", timeout_ms=300)
    assert result.status is RunStatus.ok
    assert all(f.id in {"NET-OPEN-PORT", "NET-RISKY-PORT"} for f in result.findings)

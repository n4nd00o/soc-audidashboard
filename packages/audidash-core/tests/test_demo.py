"""`audidash demo`: asset bootstrap and the three lab runs, against the in-process server."""

import datetime as dt
import json
from pathlib import Path

import pytest
from audidash_core.cli import main
from audidash_core.findings import Category, Finding, Severity
from audidash_core.manifest import load_manifest
from audidash_core.runner import RunInput, RunResult, RunStatus
from audidash_server.models import Asset, FindingRecord, Run
from sqlalchemy import select
from test_cli import REPO_PLUGINS, make_plugin
from test_client import Env, env, ready  # noqa: F401 - fixtures used by name

_BODY = """\
params = payload["parameters"]
print(json.dumps({"findings": [{"id": "DEMO-1", "title": "Demo", "severity": "high",
    "category": "misconfiguration", "target": payload["target"],
    "evidence": json.dumps(params, sort_keys=True)}], "warnings": []}))
"""


@pytest.fixture
def fake_plugins(tmp_path: Path) -> Path:
    """Unsigned stand-ins with the bundled ids: community trust, echo their parameters."""
    directory = tmp_path / "lab-plugins"
    directory.mkdir()
    parameters = {
        "http-security-headers": ({"url": {"type": "string", "default": ""}}, ["web"]),
        "tls-certificate-check": (
            {"port": {"type": "integer", "default": 443}},
            ["web", "network"],
        ),
        "network-port-scan": ({"ports": {"type": "list", "default": []}}, ["network"]),
    }
    for plugin_id, (params, targets) in parameters.items():
        make_plugin(directory, _BODY, plugin_id=plugin_id, parameters=params, targets=targets)
    return directory


def _demo(plugins: Path) -> int:
    return main(["demo", "--plugins-dir", str(plugins)])


def _assets(env: Env) -> dict[str, Asset]:
    with env.app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return {a.name: a for a in s.scalars(select(Asset))}


def test_demo_creates_assets_runs_and_uploads(
    ready: Env, fake_plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    assert _demo(fake_plugins) == 0
    out = capsys.readouterr()
    assets = _assets(ready)
    assert {"lab-web", "lab-tls", "lab-redis"} <= set(assets)
    web, tls, redis = assets["lab-web"], assets["lab-tls"], assets["lab-redis"]
    assert (web.address, web.asset_type.value, web.criticality.value) == (
        "127.0.0.1",
        "web",
        "medium",
    )
    assert web.tags == ["demo", "lab"]
    assert (tls.criticality.value, redis.asset_type.value) == ("high", "network")
    assert len(ready.runs()) == 3
    with ready.app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        by_asset = {
            f.plugin_id: (f.asset_id, json.loads(f.evidence))
            for f in s.scalars(select(FindingRecord))
        }
        targets = {r.plugin_id: r.asset_id for r in s.scalars(select(Run))}
    assert by_asset["http-security-headers"][1] == {"url": "http://127.0.0.1:18080/"}
    assert by_asset["tls-certificate-check"][1] == {"port": 18443}
    assert by_asset["network-port-scan"][1] == {"ports": [16379, 18080, 18443]}
    assert targets == {
        "http-security-headers": web.id,
        "tls-certificate-check": tls.id,
        "network-port-scan": redis.id,
    }
    text = out.out + out.err
    assert text.count("Uploaded:") == 3
    assert "community" in text.lower() and "bundled" in text.lower()
    assert "https://testserver" in out.out  # dashboard URL


def test_demo_is_repeatable(ready: Env, fake_plugins: Path) -> None:
    assert _demo(fake_plugins) == 0
    assert _demo(fake_plugins) == 0
    assert sorted(n for n in _assets(ready) if n.startswith("lab-")) == [
        "lab-redis",
        "lab-tls",
        "lab-web",
    ]
    assert len(_assets(ready)) == 4  # plus the fixture asset: nothing duplicated
    assert len(ready.runs()) == 6


def test_demo_requires_enrolment(
    env: Env, fake_plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _demo(fake_plugins) == 1
    assert "audidash enroll" in capsys.readouterr().err


def test_demo_requires_login(
    env: Env, fake_plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env.enroll()
    assert _demo(fake_plugins) == 1
    assert "run `audidash login`" in capsys.readouterr().err
    assert _assets(env) == {}


def _stub_run_local(
    monkeypatch: pytest.MonkeyPatch, *, findings: int = 1, warnings: list[str] | None = None
) -> None:
    """Hermetic: never execute a plugin (so nothing touches the real lab ports)."""

    def _fake(plugin_dir: Path, run_input: RunInput, **_kw: object) -> RunResult:
        manifest = load_manifest(plugin_dir)
        now = dt.datetime(2026, 11, 25, 12, 0, 5, tzinfo=dt.UTC)
        items = [
            Finding(
                id=f"STUB-{n}",
                title="Stub",
                severity=Severity.low,
                category=Category.misconfiguration,
                target=run_input.target,
            )
            for n in range(findings)
        ]
        return RunResult(
            plugin_id=manifest.id,
            plugin_version=manifest.version,
            target=run_input.target,
            status=RunStatus.ok,
            reason=None,
            findings=items,
            warnings=list(warnings or []),
            started_at=now,
            finished_at=now,
            stderr_tail="",
            manifest_sha256="0" * 64,
        )

    monkeypatch.setattr("audidash_core.cli.run_local", _fake)


def test_demo_official_plugins_need_no_community_override(
    ready: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The signed bundled plugins are not community: no override notice (run is stubbed)."""
    _stub_run_local(monkeypatch)
    capsys.readouterr()
    assert _demo(REPO_PLUGINS) == 0
    out = capsys.readouterr()
    assert "community" not in (out.out + out.err).lower()
    assert len(ready.runs()) == 3


def test_demo_plugin_warnings_are_shown_and_fail_the_demo(
    ready: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_run_local(monkeypatch, findings=0, warnings=["Could not fetch http://127.0.0.1:18080/"])
    capsys.readouterr()
    assert _demo(REPO_PLUGINS) == 1
    out = capsys.readouterr()
    assert "warning: http-security-headers on lab-web: Could not fetch" in out.err
    assert "produced no findings" in out.err
    assert "is the lab running? (docker compose ps)" in out.err
    assert "Demo complete" not in out.out
    assert len(ready.runs()) == 3  # results were still uploaded


def test_demo_zero_findings_without_warnings_still_fails(
    ready: Env, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_run_local(monkeypatch, findings=0)
    assert _demo(REPO_PLUGINS) == 1
    assert "is the lab running?" in capsys.readouterr().err


def test_demo_address_conflict_skips_that_run_with_a_hint(
    ready: Env, fake_plugins: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ready.add_asset("lab-tls", "10.0.0.9")
    capsys.readouterr()
    assert _demo(fake_plugins) == 1
    err = capsys.readouterr().err
    assert "'lab-tls' already exists with address '10.0.0.9'" in err
    assert len(ready.runs()) == 2  # the other two still ran
    assert "422" not in err


def test_demo_reports_a_failed_run_and_exits_nonzero(
    ready: Env, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / "broken"
    directory.mkdir()
    for plugin_id in ("http-security-headers", "tls-certificate-check", "network-port-scan"):
        make_plugin(
            directory,
            "raise SystemExit(3)\n",
            plugin_id=plugin_id,
            parameters={
                "url": {"type": "string", "default": ""},
                "port": {"type": "integer", "default": 1},
                "ports": {"type": "list", "default": []},
            },
            targets=["web", "network"],
        )
    capsys.readouterr()
    assert _demo(directory) == 1
    err = capsys.readouterr().err
    assert "http-security-headers" in err and "Traceback" not in err
    assert ready.runs() == []

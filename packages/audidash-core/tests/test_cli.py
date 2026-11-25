import base64
import io
import json
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml
from audidash_core.cli import main
from audidash_core.manifest import compute_hashes
from audidash_core.runner import RunResult, RunStatus
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_PLUGINS = Path(__file__).resolve().parents[3] / "plugins"

_PRELUDE = """\
import json, sys
payload = json.loads(sys.stdin.read())
"""


def make_plugin(
    plugins_dir: Path,
    body: str = "",
    *,
    plugin_id: str = "demo-plugin",
    **overrides: Any,
) -> Path:
    plugin_dir = plugins_dir / plugin_id
    plugin_dir.mkdir(parents=True)
    source = body or (
        'print(json.dumps({"findings": [{"id": "DEMO-1", "title": "Demo", '
        '"severity": "medium", "category": "misconfiguration", "target": payload["target"]}, '
        '{"id": "DEMO-0", "title": "Crit", "severity": "critical", '
        '"category": "vulnerability", "target": payload["target"]}], "warnings": []}))\n'
    )
    (plugin_dir / "run.py").write_text(_PRELUDE + textwrap.dedent(source), encoding="utf-8")
    data: dict[str, Any] = {
        "id": plugin_id,
        "name": "Demo",
        "version": "0.1.0",
        "author": "tester",
        "license": "Apache-2.0",
        "description": "Demo plugin",
        "runtime": "python",
        "execution": "local",
        "entrypoint": "run.py",
        "files": compute_hashes(plugin_dir, ["run.py"]),
        "targets": ["local"],
        "connection": "local",
        "permissions": ["read-only"],
        "parameters": {
            "port": {"type": "integer", "default": 1},
            "deep": {"type": "boolean", "default": False},
            "ports": {"type": "list", "default": []},
            "label": {"type": "string", "default": ""},
        },
    }
    data.update(overrides)
    (plugin_dir / "plugin.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return plugin_dir


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_list_shows_plugins(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path)
    code, out, _ = _run(["plugins", "list", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    assert "demo-plugin" in out
    assert "0.1.0" in out
    assert "community" in out
    assert "python" in out
    assert "local" in out


def test_list_shows_official_with_valid_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from audidash_core.catalog import build_index, sign_index

    make_plugin(tmp_path)
    key = Ed25519PrivateKey.generate()
    index = build_index(tmp_path)
    (tmp_path / "index.json").write_bytes(index)
    (tmp_path / "index.sig").write_bytes(base64.b64encode(sign_index(index, key)))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (tmp_path / "catalog.pub").write_bytes(base64.b64encode(raw))
    pub = tmp_path / "catalog.pub"
    argv = ["plugins", "list", "--plugins-dir", str(tmp_path)]
    # shipped inside the (untrusted) plugins dir: must be ignored
    code, out, _ = _run(argv, capsys)
    assert code == 0
    assert "official" not in out
    assert "community" in out
    # explicit override: honoured, with a notice
    code, out, err = _run([*argv, "--public-key", str(pub)], capsys)
    assert code == 0
    assert "official" in out
    assert "custom trust root" in err


def test_list_malformed_public_key_warns_not_crashes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make_plugin(tmp_path)
    bad = tmp_path / "bad.pub"
    bad.write_text("not a key!!", encoding="utf-8")
    code, out, err = _run(
        ["plugins", "list", "--plugins-dir", str(tmp_path), "--public-key", str(bad)], capsys
    )
    assert code == 0
    assert "community" in out
    assert "public key" in err.lower()


def test_show_prints_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugin = make_plugin(tmp_path)
    (plugin / "secret.txt").write_text("NOT LISTED", encoding="utf-8")
    code, out, _ = _run(["plugins", "show", "demo-plugin", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    assert "read-only" in out
    assert "run.py" in out
    assert "json.loads(sys.stdin.read())" in out
    assert "NOT LISTED" not in out


def test_show_unknown_plugin(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _run(["plugins", "show", "nope", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 2
    assert "nope" in err


def test_hash_with_manifest_prints_files_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plugin = make_plugin(tmp_path)
    code, out, _ = _run(["plugins", "hash", str(plugin)], capsys)
    assert code == 0
    parsed = yaml.safe_load(out)
    assert parsed == {"files": compute_hashes(plugin, ["run.py"])}


def test_hash_without_manifest_lists_regular_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "b.py").write_text("b", encoding="utf-8")
    (tmp_path / "a.py").write_text("a", encoding="utf-8")
    (tmp_path / "README.md").write_text("r", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("t", encoding="utf-8")
    code, out, _ = _run(["plugins", "hash", str(tmp_path)], capsys)
    assert code == 0
    parsed = yaml.safe_load(out)
    assert list(parsed["files"]) == ["a.py", "b.py"]


def test_validate_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path)
    code, out, _ = _run(["plugins", "validate", str(tmp_path)], capsys)
    assert code == 0
    assert "demo-plugin" in out


def test_validate_fails_on_tamper(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugin = make_plugin(tmp_path)
    with (plugin / "run.py").open("a", encoding="utf-8") as fh:
        fh.write("# tampered\n")
    code, _, err = _run(["plugins", "validate", str(tmp_path)], capsys)
    assert code == 1
    assert "demo-plugin" in err


def test_validate_real_plugins(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, _ = _run(["plugins", "validate", str(REPO_PLUGINS)], capsys)
    assert code == 0


def test_run_community_requires_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran.marker"
    body = f'open({str(marker)!r}, "w").close()\nprint(json.dumps({{"findings": []}}))\n'
    make_plugin(tmp_path / "plugins", body)
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    code, out, err = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--plugins-dir",
            str(tmp_path / "plugins"),
        ],
        capsys,
    )
    assert code == 2
    assert "json.loads(sys.stdin.read())" in out  # source was shown
    assert "Run this community plugin? [y/N]" in out
    assert not marker.exists()
    assert "authorized" in err


def test_run_non_interactive_without_yes_declines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran.marker"
    body = f'open({str(marker)!r}, "w").close()\nprint(json.dumps({{"findings": []}}))\n'
    make_plugin(tmp_path / "plugins", body)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    code, _, _ = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--plugins-dir",
            str(tmp_path / "plugins"),
        ],
        capsys,
    )
    assert code == 2
    assert not marker.exists()


def test_run_community_accepts_interactive_y(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    make_plugin(tmp_path)
    monkeypatch.setattr("sys.stdin", _Tty("y\n"))
    code, out, _ = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 0
    assert "DEMO-1" in out


def test_run_table_sorted_and_scored(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path)
    code, out, err = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 0
    report = out[out.index("Status:") :]
    assert report.index("DEMO-0") < report.index("DEMO-1")  # critical before medium
    # (10 + 3) * 1.0 -> 100 * (1 - e^(-13/20)) = 47.8
    assert "Asset score: 47.8 (moderate)" in out
    assert err.count("NOTICE:") == 1


def test_run_criticality_changes_score(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path)
    code, out, _ = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--criticality",
            "high",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 0
    assert "(high)" in out


def test_run_json_output_parses_as_RunResult(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make_plugin(tmp_path)
    code, out, err = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--json",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 0
    result = RunResult.model_validate_json(out)
    assert result.status is RunStatus.ok
    assert {f.id for f in result.findings} == {"DEMO-0", "DEMO-1"}
    assert "authorized" in err
    json.loads(out)


def test_run_error_status_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path, "sys.exit(3)\n")
    code, out, _ = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 1
    assert "error" in out


def test_run_params_are_typed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    body = (
        'p = payload["parameters"]\n'
        'print(json.dumps({"findings": [], "warnings": [json.dumps(p, sort_keys=True)]}))\n'
    )
    make_plugin(tmp_path, body)
    code, out, _ = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--json",
            "--param",
            "port=8080",
            "--param",
            "deep=yes",
            "--param",
            "ports=22,80",
            "--param",
            "label=a=b",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 0
    result = RunResult.model_validate_json(out)
    params = json.loads(result.warnings[0])
    assert params["port"] == 8080
    assert params["deep"] is True
    assert params["ports"] == [22, 80]
    assert params["label"] == "a=b"


def test_run_unknown_param_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path)
    code, _, err = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--param",
            "bogus=1",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 2
    assert "bogus" in err
    assert "port" in err


@pytest.mark.parametrize("param", ["port=abc", "deep=maybe", "noequals"])
def test_run_invalid_param_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], param: str
) -> None:
    make_plugin(tmp_path)
    code, _, _ = _run(
        [
            "run",
            "demo-plugin",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--param",
            param,
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 2


def test_run_unknown_plugin_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _run(
        [
            "run",
            "nope",
            "--target",
            "h",
            "--target-type",
            "local",
            "--yes",
            "--plugins-dir",
            str(tmp_path),
        ],
        capsys,
    )
    assert code == 2
    assert "nope" in err


def test_list_empty_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(["plugins", "list", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    assert "ID" in out

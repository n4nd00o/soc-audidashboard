"""CLI output hardening: plugin-controlled text must never reach the terminal raw."""

from dataclasses import replace
from pathlib import Path

import pytest
from audidash_core import cli
from audidash_core.catalog import CatalogEntry, Trust, load_catalog
from audidash_core.cli_format import clean, clean_line
from test_cli import _run, _Tty, make_plugin

EVIL = "x\x1b[31m\nFORGED\ty\x85z"
RUN_ARGV = ["run", "demo-plugin", "--target", "h", "--target-type", "local", "--yes"]


def _assert_escaped(text: str) -> None:
    assert "\x1b" not in text
    assert "\x85" not in text
    assert "\\x1b" in text


def test_show_escapes_plugin_controlled_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make_plugin(
        tmp_path,
        name=EVIL,
        description=EVIL,
        permissions=[EVIL + "\ntrust:       official"],
        parameters={EVIL: {"type": "string", "description": EVIL}},
    )
    code, out, _ = _run(["plugins", "show", "demo-plugin", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    _assert_escaped(out)
    assert not any(ln.startswith("trust:       official") for ln in out.splitlines())
    assert not any(line.startswith("FORGED") for line in out.splitlines())
    assert "\\x0a" in out


def test_run_escapes_title_and_warning(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    body = (
        'evil = "T\\x1b[31m\\ncritical  FORGED-1  x  y\\nAsset score: 0.0 (low)"\n'
        'print(json.dumps({"findings": [{"id": "REAL-1", "title": evil, "severity": "low", '
        '"category": "misconfiguration", "target": "h"}], "warnings": [evil]}))\n'
    )
    make_plugin(tmp_path, body)
    code, out, _ = _run([*RUN_ARGV, "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    report = out[out.index("Status:") :]
    _assert_escaped(report)
    lines = report.splitlines()
    assert not any(ln.startswith("critical  FORGED") for ln in lines)
    assert sum(ln.startswith("Asset score:") for ln in lines) == 1


def test_unknown_param_error_escapes_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make_plugin(tmp_path, parameters={EVIL: {"type": "string"}})
    code, _, err = _run([*RUN_ARGV, "--param", "bogus=1", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 2
    _assert_escaped(err)
    assert not any(ln.startswith("FORGED") for ln in err.splitlines())


def test_clean_helpers() -> None:
    assert clean_line("a\nb\tc\rd\x1b ") == "a\\x0ab\\x09c\\x0dd\\x1b\\u2028"
    assert clean("a\nb\tc\x1b") == "a\nb\tc\\x1b"


def test_err_sanitizes_every_message(capsys: pytest.CaptureFixture[str]) -> None:
    cli._err("FAILED  bad\x1b[2J\nname")
    assert capsys.readouterr().err == "FAILED  bad\\x1b[2J\\x0aname\n"


def test_validate_failure_message_escapes_directory_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    try:
        plugin = make_plugin(tmp_path)
        target = plugin.rename(tmp_path / "bad\x1b[2Jdir")
    except OSError:
        pytest.skip("filesystem does not allow control characters in names")
    (target / "run.py").write_text("tampered", encoding="utf-8")
    code, out, err = _run(["plugins", "validate", str(tmp_path)], capsys)
    assert code == 1
    assert "\x1b" not in out + err


def test_duplicate_plugin_ids_are_ambiguous(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("copy-one", "copy-two"):
        make_plugin(tmp_path).rename(tmp_path / name)
    argv = ["--plugins-dir", str(tmp_path)]
    for cmd in (["plugins", "show", "demo-plugin"], RUN_ARGV):
        code, _, err = _run([*cmd, *argv], capsys)
        assert code == 2
        assert "ambiguous" in err
        assert "copy-one" in err
        assert "copy-two" in err


def test_show_unreadable_source_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugin = make_plugin(tmp_path)
    (plugin / "run.py").unlink()
    code, out, err = _run(
        ["plugins", "show", "demo-plugin", "--plugins-dir", str(tmp_path)], capsys
    )
    assert code == 1
    assert "Traceback" not in out + err
    assert "cannot read source" in err


def test_run_unreadable_source_runs_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plugin = make_plugin(tmp_path)
    (plugin / "run.py").unlink()
    (plugin / "run.py").mkdir()  # a directory where a file is expected
    code, out, err = _run([*RUN_ARGV, "--plugins-dir", str(tmp_path)], capsys)
    assert code == 1
    assert "Traceback" not in out + err
    assert "was not run" in err


BACKSLASH = chr(92)
INVISIBLE = [
    *(chr(c) for c in range(0x202A, 0x202F)),
    *(chr(c) for c in range(0x2066, 0x206A)),
    *(chr(c) for c in range(0x200B, 0x2010)),
    chr(0xFEFF),
]
RLO, LRI, PDI, ZWSP = chr(0x202E), chr(0x2066), chr(0x2069), chr(0x200B)
TROJAN_WARNING = "WARNING: source contains invisible or bidirectional"


def _esc(char: str) -> str:
    return BACKSLASH + f"u{ord(char):04x}"


@pytest.mark.parametrize("char", INVISIBLE)
def test_clean_escapes_bidi_and_invisible(char: str) -> None:
    assert clean(f"a{char}b") == f"a{_esc(char)}b"
    assert clean_line(f"a{char}b") == f"a{_esc(char)}b"


@pytest.mark.parametrize("char", [chr(0x2028), chr(0x2029)])
def test_clean_escapes_line_separators(char: str) -> None:
    assert clean(f"a{char}b") == f"a{_esc(char)}b"


def test_run_warns_on_trojan_source_before_prompt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    body = (
        f'access = "user{RLO} {LRI}# admin only{PDI} {LRI}"\n'
        'print(json.dumps({"findings": []}))\n'
    )
    make_plugin(tmp_path, body)
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    argv = ["run", "demo-plugin", "--target", "h", "--plugins-dir", str(tmp_path)]
    code, out, _ = _run(argv, capsys)
    assert code == 2
    assert RLO not in out
    assert _esc(RLO) in out
    assert out.index(TROJAN_WARNING) < out.index("Run this community plugin? [y/N]")


def test_show_warns_on_trojan_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_plugin(tmp_path, f'x = "{ZWSP}"\n')
    code, out, _ = _run(["plugins", "show", "demo-plugin", "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    assert TROJAN_WARNING in out


def test_clean_source_has_no_trojan_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make_plugin(tmp_path)
    _, out, err = _run([*RUN_ARGV, "--plugins-dir", str(tmp_path)], capsys)
    assert "WARNING: source contains" not in out + err


@pytest.mark.parametrize("json_mode", [False, True])
def test_run_shows_permissions_summary_before_execution(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    json_mode: bool,
) -> None:
    marker = tmp_path / "ran.marker"
    make_plugin(
        tmp_path / "plugins",
        f'open({str(marker)!r}, "w").close()\nprint(json.dumps({{"findings": []}}))\n',
        permissions=["reads /etc/ssh/sshd_config"],
    )
    monkeypatch.setattr("sys.stdin", _Tty("n\n"))
    argv = ["run", "demo-plugin", "--target", "h", "--plugins-dir", str(tmp_path / "plugins")]
    code, out, err = _run([*argv, "--json"] if json_mode else argv, capsys)
    assert code == 2
    assert not marker.exists()
    info = err if json_mode else out
    assert "permissions:" in info
    assert "  - reads /etc/ssh/sshd_config" in info
    assert "connection:  local" in info
    assert "runtime:     python" in info
    assert "port (integer)" in info  # parameters
    assert info.index("permissions:") < info.index("Run this community plugin?")
    if json_mode:
        assert "permissions:" not in out


def test_trusted_run_also_shows_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    make_plugin(tmp_path, permissions=["reads nothing"])

    def as_verified(plugins_dir: Path, public_key: object) -> list[CatalogEntry]:
        return [replace(e, trust=Trust.verified) for e in load_catalog(plugins_dir, None)]

    monkeypatch.setattr(cli, "load_catalog", as_verified)
    code, out, _ = _run([*RUN_ARGV, "--plugins-dir", str(tmp_path)], capsys)
    assert code == 0
    assert "  - reads nothing" in out
    assert "trust:       verified" in out
    assert out.index("permissions:") < out.index("Status:")

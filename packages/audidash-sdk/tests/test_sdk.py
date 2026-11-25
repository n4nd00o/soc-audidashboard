import io
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from audidash_core.findings import PluginOutput
from audidash_sdk import Reporter, read_input, run

_SDK_SRC = Path(__file__).resolve().parents[1] / "src"


def _run_script(code: str, stdin: str) -> subprocess.CompletedProcess[str]:
    env_code = f"import sys; sys.path.insert(0, {str(_SDK_SRC)!r})\n" + textwrap.dedent(code)
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", env_code],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_reporter_emits_schema_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    reporter = Reporter("host-01")
    reporter.add(
        "SSH-ROOT",
        "Root login enabled",
        "high",
        "misconfiguration",
        evidence="PermitRootLogin yes",
        recommendation="Set PermitRootLogin no",
        references=["https://example.org/ssh"],
        item_key="sshd_config",
    )
    reporter.add("MIN-1", "Minimal", "info", "compliance")
    reporter.warn("one check skipped")
    reporter.emit()
    output = PluginOutput.model_validate_json(capsys.readouterr().out)
    assert [f.id for f in output.findings] == ["SSH-ROOT", "MIN-1"]
    assert all(f.target == "host-01" for f in output.findings)
    assert output.warnings == ["one check skipped"]


def test_reporter_rejects_unknown_severity_and_category() -> None:
    reporter = Reporter("t")
    with pytest.raises(ValueError, match="severity"):
        reporter.add("X-1", "t", "urgent", "misconfiguration")
    with pytest.raises(ValueError, match="category"):
        reporter.add("X-1", "t", "low", "other")


def test_read_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"target": "h", "parameters": {}}'))
    assert read_input()["target"] == "h"


def test_run_fills_target_and_emits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"target": "srv"}'))

    def main(data: dict[str, Any], reporter: Reporter) -> None:
        reporter.add("A-1", "t", "low", "vulnerability")

    run(main)
    output = PluginOutput.model_validate_json(capsys.readouterr().out)
    assert output.findings[0].target == "srv"


def test_run_handles_exception() -> None:
    result = _run_script(
        """
        from audidash_sdk import run
        def main(data, reporter):
            secret = "hunter2-local-variable"
            raise RuntimeError("boom")
        run(main)
        """,
        '{"target": "h"}',
    )
    assert result.returncode == 1
    assert "RuntimeError: boom" in result.stderr
    assert "Traceback" not in result.stderr
    assert "hunter2" not in result.stderr
    assert result.stdout == ""


def test_sdk_does_not_import_core_or_third_party() -> None:
    result = _run_script(
        """
        import sys
        import audidash_sdk
        bad = [m for m in sys.modules if m.split(".")[0] in ("audidash_core", "pydantic", "yaml")]
        print(len(bad))
        """,
        "",
    )
    assert result.stdout.strip() == "0"

import hashlib
import json
import os
import subprocess
import sys
import textwrap
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from audidash_core.manifest import Runtime, TargetType, compute_hashes, load_manifest
from audidash_core.runner import (
    MAX_STDOUT_BYTES,
    RunInput,
    RunStatus,
    interpreter_argv,
    run_local,
)

# Prepended to every fake plugin: reads the stdin payload and offers an emit() helper.
_PRELUDE = """\
import json, os, sys
payload = json.loads(sys.stdin.read())
def emit(findings=(), warnings=()):
    sys.stdout.write(json.dumps({"findings": list(findings), "warnings": list(warnings)}))
def finding(**kw):
    base = {"id": "DEMO-1", "title": "Demo", "severity": "low",
            "category": "misconfiguration", "target": payload["target"]}
    base.update(kw)
    return base
"""


def make_plugin(
    base: Path,
    body: str,
    *,
    name: str = "demo-plugin",
    extra_files: dict[str, bytes] | None = None,
    **overrides: Any,
) -> Path:
    plugin_dir = base / name
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "run.py").write_text(_PRELUDE + textwrap.dedent(body), encoding="utf-8")
    for rel, content in (extra_files or {}).items():
        (plugin_dir / rel).write_bytes(content)
    data: dict[str, Any] = {
        "id": "demo-plugin",
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
    }
    data.update(overrides)
    (plugin_dir / "plugin.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return plugin_dir


def _input(**kw: Any) -> RunInput:
    kw.setdefault("target", "host-01")
    kw.setdefault("target_type", TargetType.local)
    return RunInput(**kw)


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        out = subprocess.run(  # noqa: S603
            ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        return f'"{pid}"' in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_runs_python_plugin(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit([finding()])\n")
    result = run_local(plugin, _input(target="srv-42"))
    assert result.status is RunStatus.ok, result
    assert result.reason is None
    assert [f.target for f in result.findings] == ["srv-42"]
    assert result.plugin_id == "demo-plugin"
    assert result.plugin_version == "0.1.0"
    assert result.target == "srv-42"
    assert result.started_at.utcoffset() == timedelta(0)
    assert result.finished_at.utcoffset() == timedelta(0)
    assert result.finished_at >= result.started_at


def test_blocked_on_tamper(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    with (plugin / "run.py").open("a", encoding="utf-8") as fh:
        fh.write("# tampered\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("integrity")
    assert result.findings == []


def test_blocked_on_bad_manifest(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    (plugin / "plugin.yaml").write_text("a: [unclosed", encoding="utf-8")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("manifest")


def test_remote_execution_rejected(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n", execution="remote")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.blocked
    assert result.reason == "remote_not_supported"


def test_unlisted_files_not_available(tmp_path: Path) -> None:
    body = """\
    here = os.path.dirname(os.path.abspath(__file__))
    emit(warnings=[str(os.path.exists(os.path.join(here, "extra.txt")))])
    """
    plugin = make_plugin(tmp_path, body, extra_files={"extra.txt": b"unhashed"})
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert result.warnings == ["False"]


def test_env_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIDASH_TEST_SECRET", "x")
    plugin = make_plugin(tmp_path, "emit(warnings=[','.join(sorted(os.environ))])\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    keys = result.warnings[0].upper().split(",")
    assert "AUDIDASH_TEST_SECRET" not in keys
    assert "PATH" in keys


def test_credentials_via_stdin_only(tmp_path: Path) -> None:
    secret = "s3cr3t-v4lue-QWERTY"  # noqa: S105 - test fixture
    body = f"""\
    secret = {secret!r}
    emit(warnings=[
        "argv:" + str(secret in json.dumps(sys.argv)),
        "env:" + str(secret in json.dumps(dict(os.environ))),
        "stdin:" + str(payload["credentials"].get("token") == secret),
        "params:" + str(payload["parameters"] == {{"depth": 2}}),
        "type:" + payload["target_type"],
    ])
    """
    plugin = make_plugin(tmp_path, body)
    run_input = _input(parameters={"depth": 2}, credentials={"token": secret})
    assert secret not in repr(run_input)
    assert secret not in str(run_input)
    assert secret not in run_input.model_dump_json()
    result = run_local(plugin, run_input)
    assert result.status is RunStatus.ok, result
    assert result.warnings == [
        "argv:False",
        "env:False",
        "stdin:True",
        "params:True",
        "type:local",
    ]
    assert secret not in result.model_dump_json()


def test_timeout_kills_tree(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    body = """\
    import subprocess, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    with open(payload["parameters"]["pid_file"], "w") as fh:
        fh.write(str(child.pid))
    time.sleep(60)
    """
    plugin = make_plugin(tmp_path, body)
    started = time.monotonic()
    result = run_local(plugin, _input(parameters={"pid_file": str(pid_file)}), timeout_s=2)
    assert time.monotonic() - started < 30
    assert result.status is RunStatus.timeout
    assert result.findings == []
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _pid_alive(pid)


def test_output_cap(tmp_path: Path) -> None:
    body = """\
    chunk = b"x" * (1024 * 1024)
    for _ in range(11):
        sys.stdout.buffer.write(chunk)
    sys.stdout.flush()
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input())
    assert MAX_STDOUT_BYTES == 10 * 1024 * 1024
    assert result.status is RunStatus.error
    assert result.reason == "output_too_large"
    assert result.findings == []


@pytest.mark.parametrize("raw", [b"\xff\xfe", b"not json", b'{"findings": [{"id": "x"}]}'])
def test_invalid_output(tmp_path: Path, raw: bytes) -> None:
    body = f"sys.stdout.buffer.write({raw!r})\n"
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input())
    assert result.status is RunStatus.error
    assert result.reason == "invalid_output"
    assert result.findings == []


def test_nonzero_exit_with_valid_output(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit([finding()])\nsys.exit(3)\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.error
    assert result.reason == "exit_code:3"
    assert result.findings == []


def test_nonzero_exit_with_invalid_output(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "print('garbage')\nsys.exit(2)\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.error
    assert result.reason == "exit_code:2"


def test_findings_are_sanitized(tmp_path: Path) -> None:
    body = """\
    emit([finding(evidence="key=AKIAIOSFODNN7EXAMPLE")], ["seen AKIAIOSFODNN7EXAMPLE"])
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert "AKIAIOSFODNN7EXAMPLE" not in result.model_dump_json()
    assert "[REDACTED:aws_access_key]" in result.findings[0].evidence


def test_stderr_tail_bounded_and_redacted(tmp_path: Path) -> None:
    body = """\
    sys.stderr.write("A" * (2 * 1024 * 1024))
    sys.stderr.write("\\nleak AKIAIOSFODNN7EXAMPLE end\\n")
    sys.stderr.flush()
    emit()
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert len(result.stderr_tail.encode("utf-8")) <= 4096 + 64
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stderr_tail
    assert "[REDACTED:aws_access_key]" in result.stderr_tail


def test_runs_from_path_with_space(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path / "with space", "emit([finding()])\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert len(result.findings) == 1


def test_interpreter_argv() -> None:
    entry = Path("/plugins/x/run")
    argv = interpreter_argv(Runtime.python, entry, sdk_dir=Path("/sdk"), plugin_root=Path("/p"))
    assert argv[:4] == [sys.executable, "-I", "-S", "-c"]
    assert argv[5:] == [str(Path("/sdk")), str(Path("/p")), str(entry)]
    assert interpreter_argv(Runtime.powershell, entry) == [
        "pwsh",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(entry),
    ]
    assert interpreter_argv(Runtime.bash, entry) == ["bash", "--noprofile", "--norc", str(entry)]


def test_result_serializes(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit([finding()])\n")
    dumped = json.loads(run_local(plugin, _input()).model_dump_json())
    assert dumped["status"] == "ok"


def _rewrite_files(plugin: Path, files: dict[str, str]) -> None:
    path = plugin / "plugin.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["files"] = files
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_blocked_on_file_used_as_directory(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    digest = compute_hashes(plugin, ["run.py"])["run.py"]
    _rewrite_files(plugin, {"run.py": digest, "run.py/x": digest})
    result = run_local(plugin, _input())
    assert result.status is RunStatus.blocked
    assert result.reason is not None
    assert result.reason.startswith(("manifest", "integrity"))


def test_blocked_on_nul_in_file_path(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    digest = compute_hashes(plugin, ["run.py"])["run.py"]
    _rewrite_files(plugin, {"run.py": digest, "a\x00b": digest})
    result = run_local(plugin, _input())
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("manifest")


def test_unexpected_exception_becomes_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import audidash_core.runner as runner_mod

    def boom(*_: object) -> None:
        raise RuntimeError("raw detail must not leak")

    monkeypatch.setattr(runner_mod, "_stage_copy", boom)
    plugin = make_plugin(tmp_path, "emit()\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.error
    assert result.reason == "internal_error:RuntimeError"


def test_leftover_children_killed_after_normal_exit(tmp_path: Path) -> None:
    body = """\
    import subprocess
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        )
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **kwargs,
    )
    emit(warnings=["pid:" + str(child.pid)])
    """
    plugin = make_plugin(tmp_path, body)
    started = time.monotonic()
    result = run_local(plugin, _input(), timeout_s=20)
    assert time.monotonic() - started < 15
    assert result.status is RunStatus.ok, result
    pid = int(result.warnings[0].removeprefix("pid:"))
    deadline = time.monotonic() + 5
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _pid_alive(pid)


def test_known_credentials_scrubbed(tmp_path: Path) -> None:
    secret = "hunter2-plain-value"  # noqa: S105 - test fixture
    body = """\
    s = payload["credentials"]["token"]
    sys.stderr.write("stderr " + s + " end\\n")
    emit(
        [finding(title="t " + s, evidence="e " + s, recommendation="r " + s)],
        ["w " + s],
    )
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input(credentials={"token": secret, "short": "abc"}))
    assert result.status is RunStatus.ok, result
    assert secret not in result.model_dump_json()
    marker = "[REDACTED:credential]"
    f = result.findings[0]
    assert marker in f.title and marker in f.evidence and marker in f.recommendation
    assert marker in result.warnings[0]
    assert marker in result.stderr_tail


def test_sdk_available_to_python_plugins(tmp_path: Path) -> None:
    body = """
    from audidash_sdk import Reporter
    r = Reporter(payload["target"])
    r.add("SDK-1", "From SDK", "low", "misconfiguration")
    r.emit()
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert [f.id for f in result.findings] == ["SDK-1"]


def test_plugin_cannot_import_core(tmp_path: Path) -> None:
    body = """
    warnings = []
    for mod in ("audidash_core", "pydantic"):
        try:
            __import__(mod)
        except ImportError as exc:
            warnings.append("ImportError " + mod)
    emit(warnings=warnings)
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert result.warnings == ["ImportError audidash_core", "ImportError pydantic"]


def test_sdk_dir_contains_only_sdk(tmp_path: Path) -> None:
    body = """
    emit(warnings=[",".join(sorted(os.listdir(sys.path[0])))])
    """
    result = run_local(make_plugin(tmp_path, body), _input())
    assert result.status is RunStatus.ok, result
    assert result.warnings == ["audidash_sdk"]


def test_plugin_can_import_listed_helper(tmp_path: Path) -> None:
    plugin = make_plugin(
        tmp_path,
        """
        import helper
        emit(warnings=[helper.VALUE])
        """,
        extra_files={"helper.py": b'VALUE = "from-helper"\n'},
    )
    manifest_path = plugin / "plugin.yaml"
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    data["files"] = compute_hashes(plugin, ["run.py", "helper.py"])
    manifest_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.ok, result
    assert result.warnings == ["from-helper"]


# ---------------------------------------------------------------- reviewed-manifest pin


def _yaml_sha256(plugin: Path) -> str:
    return hashlib.sha256((plugin / "plugin.yaml").read_bytes()).hexdigest()


def _swap_code(plugin: Path, marker: Path) -> None:
    """Replace run.py with code that drops ``marker`` and re-hash plugin.yaml consistently."""
    (plugin / "run.py").write_text(
        f"open({str(marker)!r}, 'w').close()\nprint('{{\"findings\": []}}')\n", encoding="utf-8"
    )
    _rewrite_files(plugin, compute_hashes(plugin, ["run.py"]))


def test_pinned_manifest_sha256_mismatch_blocks(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    reviewed_sha = _yaml_sha256(plugin)
    marker = tmp_path / "ran.marker"
    _swap_code(plugin, marker)
    result = run_local(plugin, _input(), expected_manifest_sha256=reviewed_sha)
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("integrity")
    assert result.manifest_sha256 is None
    assert not marker.exists()


def test_pinned_manifest_object_mismatch_blocks(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    reviewed = load_manifest(plugin)
    marker = tmp_path / "ran.marker"
    _swap_code(plugin, marker)
    result = run_local(plugin, _input(), expected_manifest=reviewed)
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("integrity")
    assert not marker.exists()


def test_pinned_manifest_blocks_unparseable_replacement(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    reviewed_sha = _yaml_sha256(plugin)
    (plugin / "plugin.yaml").write_text("a: [unclosed", encoding="utf-8")
    result = run_local(plugin, _input(), expected_manifest_sha256=reviewed_sha)
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("integrity")


def test_pinned_manifest_files_checked_against_pin(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    reviewed, reviewed_sha = load_manifest(plugin), _yaml_sha256(plugin)
    (plugin / "run.py").write_text("raise SystemExit(3)\n", encoding="utf-8")
    result = run_local(
        plugin, _input(), expected_manifest=reviewed, expected_manifest_sha256=reviewed_sha
    )
    assert result.status is RunStatus.blocked
    assert result.reason is not None and result.reason.startswith("integrity")


def test_pinned_manifest_match_runs_and_reports_digest(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit([finding()])\n")
    reviewed, reviewed_sha = load_manifest(plugin), _yaml_sha256(plugin)
    result = run_local(
        plugin, _input(), expected_manifest=reviewed, expected_manifest_sha256=reviewed_sha
    )
    assert result.status is RunStatus.ok, result
    assert result.manifest_sha256 == reviewed_sha
    assert result.trust is None


def test_manifest_sha256_reported_without_pin(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    assert run_local(plugin, _input()).manifest_sha256 == _yaml_sha256(plugin)


def test_manifest_sha256_none_when_blocked_before_load(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, "emit()\n")
    (plugin / "plugin.yaml").write_text("a: [unclosed", encoding="utf-8")
    assert run_local(plugin, _input()).manifest_sha256 is None


# ---------------------------------------------------------------- finding attribution / limits


def test_finding_target_forced_to_run_target(tmp_path: Path) -> None:
    plugin = make_plugin(tmp_path, 'emit([finding(target="someone-elses-asset")])\n')
    result = run_local(plugin, _input(target="srv-42"))
    assert result.status is RunStatus.ok, result
    assert [f.target for f in result.findings] == ["srv-42"]


def test_references_scrubbed_and_redacted(tmp_path: Path) -> None:
    secret = "plain-cred-value-99"  # noqa: S105 - test fixture
    body = """\
    s = payload["credentials"]["k"]
    emit([finding(references=["https://x.example/?token=abc", "see " + s, "https://ok.example"])])
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input(credentials={"k": secret}))
    assert result.status is RunStatus.ok, result
    refs = result.findings[0].references
    assert refs == [
        "https://x.example/?token=[REDACTED:token]",
        "see [REDACTED:credential]",
        "https://ok.example",
    ]


def test_item_key_redaction_keeps_value_and_warns(tmp_path: Path) -> None:
    body = """\
    emit([
        finding(id="KEY-1", item_key="user joao@empresa.com.br"),
        finding(id="KEY-2", item_key="cred " + payload["credentials"]["k"]),
        finding(id="KEY-3", item_key="/etc/ssh/sshd_config"),
    ])
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input(credentials={"k": "plain-cred-value-99"}))
    assert result.status is RunStatus.ok, result
    keys = {f.id: f.item_key for f in result.findings}
    assert keys == {
        "KEY-1": "user [REDACTED:email]",
        "KEY-2": "cred [REDACTED:credential]",
        "KEY-3": "/etc/ssh/sshd_config",
    }
    assert "item_key redacted for KEY-1" in result.warnings
    assert "item_key redacted for KEY-2" in result.warnings
    assert not any("KEY-3" in w for w in result.warnings)


@pytest.mark.parametrize(
    "kw",
    [
        'item_key="k" * 256',
        'references=["r" * 201]',
        'references=["r"] * 51',
    ],
)
def test_oversized_item_key_or_references_rejected(tmp_path: Path, kw: str) -> None:
    plugin = make_plugin(tmp_path, f"emit([finding({kw})])\n")
    result = run_local(plugin, _input())
    assert result.status is RunStatus.error
    assert result.reason == "invalid_output"


# ---------------------------------------------------------------- stderr / interpreters


def test_stderr_scrubbed_before_redaction(tmp_path: Path) -> None:
    secret = "mysecretvalue joao@empresa.com.br"  # noqa: S105 - test fixture
    body = """\
    sys.stderr.write("err " + payload["credentials"]["k"] + " end\\n")
    raise SystemExit(1)
    """
    plugin = make_plugin(tmp_path, body)
    result = run_local(plugin, _input(credentials={"k": secret}))
    assert result.status is RunStatus.error
    assert "mysecretvalue" not in result.stderr_tail
    assert "[REDACTED:credential]" in result.stderr_tail


def test_missing_interpreter_reports_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = tmp_path / "sh-plugin"
    plugin.mkdir()
    (plugin / "run.sh").write_text("echo '{\"findings\": []}'\n", encoding="utf-8")
    data = {
        "id": "sh-plugin",
        "name": "Sh",
        "version": "0.1.0",
        "author": "tester",
        "license": "Apache-2.0",
        "description": "Bash plugin",
        "runtime": "bash",
        "execution": "local",
        "entrypoint": "run.sh",
        "files": compute_hashes(plugin, ["run.sh"]),
        "targets": ["local"],
        "connection": "local",
        "permissions": ["read-only"],
    }
    (plugin / "plugin.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    result = run_local(plugin, _input())
    assert result.status is RunStatus.error
    assert result.reason == "interpreter_not_found:bash"

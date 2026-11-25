"""Isolated local plugin runner.

A run copies the hashed plugin files into a fresh temporary directory, checks
the copied bytes against the manifest and executes the copy in a subprocess
with a minimal environment, a timeout and a stdout size cap. Credentials are
sent only in the stdin JSON payload. The plugin's output is validated and every
finding is sanitized before it leaves this module.
"""

import contextlib
import json
import os
import subprocess
import sys
import tempfile
import threading
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import IO

from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError

from audidash_core.findings import Finding, PluginOutput
from audidash_core.manifest import (
    Execution,
    IntegrityError,
    ManifestError,
    PluginManifest,
    Runtime,
    TargetType,
    load_manifest,
    verify_integrity,
)
from audidash_core.proc import isolation_kwargs, kill_tree
from audidash_core.sanitizer import _redact_capped, redact, sanitize_finding

MAX_STDOUT_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT_S = 300

_STDERR_TAIL_BYTES = 4 * 1024
_CHUNK = 64 * 1024
_DRAIN_TIMEOUT_S = 5.0
_MAX_REASON_CHARS = 300
_MAX_WARNINGS = 100
_MAX_WARNING_CHARS = 1000
_WINDOWS_ENV_KEYS = ("SYSTEMROOT", "COMSPEC", "PATHEXT")
_HOME_ENV_KEYS = ("TEMP", "TMP", "HOME", "USERPROFILE")


class RunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    target_type: TargetType
    parameters: dict[str, object] = {}
    credentials: dict[str, SecretStr] = {}


class RunStatus(StrEnum):
    ok = "ok"
    error = "error"
    timeout = "timeout"
    blocked = "blocked"


class RunResult(BaseModel):
    plugin_id: str
    plugin_version: str
    target: str
    status: RunStatus
    reason: str | None
    findings: list[Finding]
    warnings: list[str]
    started_at: datetime
    finished_at: datetime
    stderr_tail: str


def interpreter_argv(runtime: Runtime, entrypoint: Path) -> list[str]:
    """Command line that runs ``entrypoint`` with the runtime's interpreter."""
    entry = str(entrypoint)
    if runtime is Runtime.python:
        return [sys.executable, "-I", entry]
    if runtime is Runtime.powershell:
        return ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", entry]
    return ["bash", "--noprofile", "--norc", entry]


def _now() -> datetime:
    return datetime.now(UTC)


def _short(message: str) -> str:
    return redact(message[: _MAX_REASON_CHARS * 2])[:_MAX_REASON_CHARS]


def _clean_env(home: Path) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", os.defpath)}
    if sys.platform == "win32":
        for key in _WINDOWS_ENV_KEYS:
            if key in os.environ:
                env[key] = os.environ[key]
    for key in _HOME_ENV_KEYS:
        env[key] = str(home)
    return env


def _stage_copy(plugin_dir: Path, manifest: PluginManifest, dest: Path) -> None:
    """Copy the hashed files into ``dest`` and verify the copied bytes."""
    for relative in manifest.files:
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes((plugin_dir / relative).read_bytes())
        except OSError as exc:
            raise IntegrityError(f"{plugin_dir.name}: cannot read {relative!r}: {exc}") from exc
    verify_integrity(dest, manifest)


def _payload(run_input: RunInput) -> bytes:
    return json.dumps(
        {
            "target": run_input.target,
            "target_type": run_input.target_type.value,
            "parameters": run_input.parameters,
            "credentials": {k: v.get_secret_value() for k, v in run_input.credentials.items()},
        }
    ).encode("utf-8")


class _Capture:
    """Drains a child's pipes in background threads with bounded memory."""

    def __init__(self, proc: subprocess.Popen[bytes], payload: bytes) -> None:
        self._proc = proc
        self.stdout = bytearray()
        self.stderr_tail = bytearray()
        self.stderr_truncated = False
        self.overflow = False
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            raise ValueError("process must be started with stdin/stdout/stderr pipes")
        self._threads = [
            threading.Thread(target=self._feed, args=(proc.stdin, payload), daemon=True),
            threading.Thread(target=self._read_stdout, args=(proc.stdout,), daemon=True),
            threading.Thread(target=self._read_stderr, args=(proc.stderr,), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    @staticmethod
    def _feed(stream: IO[bytes], payload: bytes) -> None:
        with contextlib.suppress(OSError):
            stream.write(payload)
        with contextlib.suppress(OSError):
            stream.close()

    def _read_stdout(self, stream: IO[bytes]) -> None:
        while chunk := stream.read1(_CHUNK):  # type: ignore[attr-defined]
            if len(self.stdout) + len(chunk) > MAX_STDOUT_BYTES:
                self.overflow = True
                kill_tree(self._proc)
                return
            self.stdout += chunk

    def _read_stderr(self, stream: IO[bytes]) -> None:
        while chunk := stream.read1(_CHUNK):  # type: ignore[attr-defined]
            self.stderr_tail += chunk
            excess = len(self.stderr_tail) - _STDERR_TAIL_BYTES
            if excess > 0:
                del self.stderr_tail[:excess]
                self.stderr_truncated = True

    def join(self, timeout: float) -> bool:
        """Wait for the pipes to close; True when every reader finished."""
        for thread in self._threads:
            thread.join(timeout)
        return not any(thread.is_alive() for thread in self._threads)


def _stderr_text(capture: _Capture) -> str:
    text = bytes(capture.stderr_tail).decode("utf-8", errors="replace")
    if capture.stderr_truncated:
        # Drop the leading partial token so a cut secret cannot leak its suffix.
        cut = min((i for i in (text.find(c) for c in " \t\r\n") if i >= 0), default=-1)
        text = text[cut + 1 :] if cut >= 0 else ""
    return redact(text)


def _parse(raw: bytes) -> PluginOutput | None:
    try:
        return PluginOutput.model_validate_json(raw)
    except (ValidationError, ValueError, RecursionError):
        return None


def run_local(
    plugin_dir: Path, run_input: RunInput, timeout_s: int = DEFAULT_TIMEOUT_S
) -> RunResult:
    """Run a local plugin in isolation; plugin failures are reported via status."""
    started_at = _now()
    plugin_id, plugin_version = plugin_dir.name, ""

    def result(
        status: RunStatus,
        reason: str | None,
        findings: list[Finding] | None = None,
        warnings: list[str] | None = None,
        stderr_tail: str = "",
    ) -> RunResult:
        return RunResult(
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            target=run_input.target,
            status=status,
            reason=reason,
            findings=findings or [],
            warnings=warnings or [],
            started_at=started_at,
            finished_at=_now(),
            stderr_tail=stderr_tail,
        )

    try:
        manifest = load_manifest(plugin_dir)
    except ManifestError as exc:
        return result(RunStatus.blocked, f"manifest: {_short(str(exc))}")
    plugin_id, plugin_version = manifest.id, manifest.version
    if manifest.execution is not Execution.local:
        return result(RunStatus.blocked, "remote_not_supported")
    try:
        payload = _payload(run_input)
    except (TypeError, ValueError):
        return result(RunStatus.error, "invalid_input")

    with tempfile.TemporaryDirectory(prefix="audidash-run-", ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        code_dir = root / (plugin_dir.resolve().name or "plugin")
        home = root / "home"
        home.mkdir()
        try:
            _stage_copy(plugin_dir, manifest, code_dir)
        except IntegrityError as exc:
            return result(RunStatus.blocked, f"integrity: {_short(str(exc))}")

        argv = interpreter_argv(manifest.runtime, code_dir / manifest.entrypoint)
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=home,
                env=_clean_env(home),
                shell=False,
                **isolation_kwargs(),
            )
        except OSError as exc:
            return result(RunStatus.error, f"spawn_failed: {_short(str(exc))}")

        capture = _Capture(proc, payload)
        timed_out = False
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_tree(proc)
            proc.wait()
        drained = capture.join(_DRAIN_TIMEOUT_S)
        if not drained:
            # A descendant still holds the pipes open: kill the group and retry.
            kill_tree(proc)
            drained = capture.join(_DRAIN_TIMEOUT_S)
        stderr_tail = _stderr_text(capture)

        if timed_out:
            return result(RunStatus.timeout, "timeout", stderr_tail=stderr_tail)
        if capture.overflow:
            return result(RunStatus.error, "output_too_large", stderr_tail=stderr_tail)
        if not drained:
            return result(RunStatus.error, "output_not_closed", stderr_tail=stderr_tail)
        if proc.returncode != 0:
            return result(RunStatus.error, f"exit_code:{proc.returncode}", stderr_tail=stderr_tail)
        output = _parse(bytes(capture.stdout))
        if output is None:
            return result(RunStatus.error, "invalid_output", stderr_tail=stderr_tail)

    findings = [sanitize_finding(f) for f in output.findings]
    warnings = [_redact_capped(w, _MAX_WARNING_CHARS) for w in output.warnings[:_MAX_WARNINGS]]
    return result(RunStatus.ok, None, findings, warnings, stderr_tail)

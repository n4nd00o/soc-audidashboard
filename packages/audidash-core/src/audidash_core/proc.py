"""Process-tree helpers: start plugins in their own group and kill the whole tree."""

import contextlib
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any


def isolation_kwargs() -> dict[str, Any]:
    """Popen kwargs that put the child in its own process group / session."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _taskkill() -> str:
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    candidate = Path(system_root) / "System32" / "taskkill.exe"
    return str(candidate) if candidate.is_file() else "taskkill"


def kill_tree(p: subprocess.Popen[bytes]) -> None:
    """Forcefully kill ``p`` and every descendant; never raises."""
    if sys.platform == "win32":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # noqa: S603 - fixed argv, no shell
                [_taskkill(), "/F", "/T", "/PID", str(p.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
    else:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(p.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        p.kill()

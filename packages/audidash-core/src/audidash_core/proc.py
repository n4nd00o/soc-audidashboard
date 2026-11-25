"""Process-tree helpers: run a plugin in its own group and kill the whole tree.

On Windows the child is assigned to a Job object configured with
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``, so every descendant (including detached
ones) dies when the job is terminated or its handle closed. On POSIX the child
leads a new session and the group is killed with ``killpg``.
"""

import contextlib
import os
import signal

# Reason: spawning plugin processes is this module's purpose (argv lists, shell=False).
import subprocess  # nosec B404
import sys
import threading
from pathlib import Path
from types import TracebackType
from typing import Any

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    def _create_kill_on_close_job() -> int | None:
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = _kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            _kernel32.CloseHandle(job)
            return None
        return int(job)

    def _assign(job: int, pid: int) -> bool:
        handle = _kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not handle:
            return False
        try:
            return bool(_kernel32.AssignProcessToJobObject(job, handle))
        finally:
            _kernel32.CloseHandle(handle)


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
    """Forcefully kill ``p`` and its descendants (best effort); never raises.

    Prefer :class:`ProcessGroup`, which also reaches orphaned descendants on Windows.
    """
    if sys.platform == "win32":
        if p.poll() is None:  # taskkill on an exited PID could hit a reused one
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                # Reason: fixed argv (taskkill), no shell, no user input beyond the pid.
                subprocess.run(  # noqa: S603  # nosec B603
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


class ProcessGroup:
    """Owns one spawned process and every descendant; ``close`` kills them all."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen[bytes] | None = None
        self._job: int | None = None
        self._lock = threading.Lock()

    def __enter__(self) -> "ProcessGroup":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def spawn(self, argv: list[str], **popen_kwargs: Any) -> subprocess.Popen[bytes]:
        """Start ``argv`` (shell=False) inside this group."""
        if self.proc is not None:
            raise RuntimeError("ProcessGroup already spawned a process")
        if sys.platform == "win32":
            self._job = _create_kill_on_close_job()
        # Reason: argv list with shell=False; the plugin path is validated by the manifest.
        proc: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603  # nosec B603
            argv, shell=False, **popen_kwargs, **isolation_kwargs()
        )
        self.proc = proc
        if sys.platform == "win32" and self._job is not None and not _assign(self._job, proc.pid):
            with self._lock:
                _kernel32.CloseHandle(self._job)
                self._job = None
        return proc

    def kill(self) -> None:
        """Kill the process and all descendants; safe to call repeatedly and concurrently."""
        proc = self.proc
        if proc is None:
            return
        if sys.platform == "win32":
            with self._lock:
                job = self._job
                if job is not None:
                    _kernel32.TerminateJobObject(job, 1)
            if job is None:
                kill_tree(proc)
        else:
            # The group outlives its leader, so this also reaches leftover children.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(OSError):
            proc.kill()

    def close(self) -> None:
        """Kill everything still running and release the job handle."""
        try:
            self.kill()
        finally:
            if sys.platform == "win32":
                with self._lock:
                    if self._job is not None:
                        _kernel32.CloseHandle(self._job)
                        self._job = None

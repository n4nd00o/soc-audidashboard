"""Per-IP sliding-window limiter for login attempts (20 per 15 minutes).

Limitation: state lives in process memory, so it is per worker process and reset on restart.
The deployment runs a single uvicorn process; a multi-process deployment would need a shared
store. Behind a reverse proxy the key is the proxy-supplied client address.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import timedelta

from audidash_server import clock

LOGIN_MAX_ATTEMPTS = 20
LOGIN_WINDOW = timedelta(minutes=15)


class LoginRateLimiter:
    def __init__(
        self, max_attempts: int = LOGIN_MAX_ATTEMPTS, window: timedelta = LOGIN_WINDOW
    ) -> None:
        self.max_attempts = max_attempts
        self.window = window.total_seconds()
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record an attempt from `key`; False if it exceeds the limit (not recorded then)."""
        now = clock.now().timestamp()
        cutoff = now - self.window
        with self._lock:
            self._prune(cutoff)
            hits = self._hits.setdefault(key, deque())
            if len(hits) >= self.max_attempts:
                return False
            hits.append(now)
            return True

    def _prune(self, cutoff: float) -> None:
        for key in list(self._hits):
            hits = self._hits[key]
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if not hits:
                del self._hits[key]

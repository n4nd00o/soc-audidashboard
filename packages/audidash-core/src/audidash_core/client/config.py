"""Per-user client configuration: device identity, pinned CA, server URLs and API token.

Files live in ``platformdirs.user_config_dir("audidash")``: ``device.key`` (never leaves the
machine), ``device.crt``, ``ca.crt`` (the pinned trust root), ``server.json`` and
``token.json`` plus ``verified.json`` (cached plugin allowlist). Secrets are written 0600
inside a 0700 directory on POSIX; on Windows the files inherit the user-profile ACL.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_config_dir

APP_NAME = "audidash"


class ClientError(Exception):
    """A failure the CLI reports as one line (never carries secrets)."""


class ConfigError(ClientError):
    """Missing or unreadable client configuration."""


class SessionExpiredError(ClientError):
    """No valid API token: the user must run ``audidash login``."""

    def __init__(self) -> None:
        super().__init__("session expired — run `audidash login`")


def utcnow() -> datetime:
    return datetime.now(UTC)


def default_config_dir() -> Path:
    return Path(user_config_dir(APP_NAME))


@dataclass(frozen=True)
class ClientConfig:
    directory: Path
    dashboard_url: str
    api_url: str
    device_id: str

    @property
    def key_path(self) -> Path:
        return self.directory / "device.key"

    @property
    def cert_path(self) -> Path:
        return self.directory / "device.crt"

    @property
    def ca_path(self) -> Path:
        return self.directory / "ca.crt"

    @property
    def token_path(self) -> Path:
        return self.directory / "token.json"


def ensure_private_dir(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(directory, 0o700)


def write_private(path: Path, data: bytes) -> None:
    """Atomically (re)write `path`, created owner-only (0600 on POSIX)."""
    temp = path.with_name(path.name + ".tmp")
    temp.unlink(missing_ok=True)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    if sys.platform != "win32":
        os.chmod(temp, 0o600)
    os.replace(temp, path)


def is_enrolled(directory: Path) -> bool:
    return (directory / "device.key").exists()


def save_enrollment(
    directory: Path,
    *,
    key_pem: bytes,
    cert_pem: bytes,
    ca_pem: bytes,
    dashboard_url: str,
    api_url: str,
    device_id: str,
) -> ClientConfig:
    ensure_private_dir(directory)
    info = {"dashboard_url": dashboard_url, "api_url": api_url, "device_id": device_id}
    write_private(directory / "device.key", key_pem)
    write_private(directory / "device.crt", cert_pem)
    write_private(directory / "ca.crt", ca_pem)
    write_private(directory / "server.json", json.dumps(info, indent=2).encode("utf-8"))
    return load_config(directory)


def load_config(directory: Path) -> ClientConfig:
    not_enrolled = ConfigError("this device is not enrolled — run `audidash enroll`")
    try:
        info = json.loads((directory / "server.json").read_text(encoding="utf-8"))
        config = ClientConfig(
            directory=directory,
            dashboard_url=str(info["dashboard_url"]),
            api_url=str(info["api_url"]),
            device_id=str(info["device_id"]),
        )
    except FileNotFoundError:
        raise not_enrolled from None
    except (OSError, ValueError, KeyError, TypeError):
        raise ConfigError(f"client configuration in {directory} is unreadable") from None
    if not (config.key_path.exists() and config.cert_path.exists() and config.ca_path.exists()):
        raise not_enrolled
    return config


def save_token(directory: Path, access_token: str, expires_at: datetime) -> None:
    ensure_private_dir(directory)
    body = {"access_token": access_token, "expires_at": expires_at.isoformat()}
    write_private(directory / "token.json", json.dumps(body).encode("utf-8"))


def load_token(directory: Path) -> str:
    """The stored API token, or SessionExpiredError when missing, malformed or expired."""
    try:
        body = json.loads((directory / "token.json").read_text(encoding="utf-8"))
        token = str(body["access_token"])
        expires_at = datetime.fromisoformat(str(body["expires_at"]))
    except (OSError, ValueError, KeyError, TypeError):
        raise SessionExpiredError from None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if not token or expires_at <= utcnow():
        raise SessionExpiredError
    return token


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def save_verified(directory: Path, hashes: Iterable[str]) -> None:
    """Cache the server's verified-manifest allowlist (last successful sync)."""
    ensure_private_dir(directory)
    body = {"manifest_sha256": sorted(set(hashes))}
    write_private(directory / "verified.json", json.dumps(body).encode("utf-8"))


def load_verified(directory: Path) -> frozenset[str]:
    """Cached allowlist; empty when missing or unreadable (never an error)."""
    try:
        body = json.loads((directory / "verified.json").read_text(encoding="utf-8"))
        items = body["manifest_sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        return frozenset()
    if not isinstance(items, list):
        return frozenset()
    return frozenset(i for i in items if isinstance(i, str) and _SHA256_HEX.fullmatch(i))

"""Plugin manifest schema (plugin.yaml) and integrity verification."""

import hashlib
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_SEMVER = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_MAX_MANIFEST_BYTES = 256 * 1024
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class Runtime(StrEnum):
    python = "python"
    powershell = "powershell"
    bash = "bash"


class Execution(StrEnum):
    local = "local"
    remote = "remote"


class TargetType(StrEnum):
    linux = "linux"
    windows = "windows"
    aws = "aws"
    azure = "azure"
    gcp = "gcp"
    m365 = "m365"
    network = "network"
    web = "web"
    local = "local"


class Connection(StrEnum):
    ssh = "ssh"
    winrm = "winrm"
    cloud_api = "cloud_api"
    network = "network"
    local = "local"


class ManifestError(Exception):
    """plugin.yaml is missing, malformed or violates the schema."""


class IntegrityError(Exception):
    """A plugin file does not match the hash recorded in its manifest."""


def _check_relative_path(value: str) -> str:
    """Syntactic check: POSIX-style relative path without escapes."""
    if not value:
        raise ValueError("path must not be empty")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"path {value!r} must not contain control characters")
    if "\\" in value:
        raise ValueError(f"path {value!r} must use forward slashes")
    if value.startswith("/") or ":" in value:
        raise ValueError(f"path {value!r} must be relative (no absolute path or drive)")
    if ".." in PurePosixPath(value).parts:
        raise ValueError(f"path {value!r} must not contain '..'")
    return value


class ParameterSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["string", "integer", "boolean", "list"]
    default: object | None = None
    description: str = ""


class PluginManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    name: str = Field(min_length=1)
    version: str = Field(pattern=_SEMVER)
    author: str = Field(min_length=1)
    license: str = Field(min_length=1)
    description: str = Field(min_length=1)
    runtime: Runtime
    execution: Execution
    entrypoint: str
    files: dict[str, str]
    targets: list[TargetType] = Field(min_length=1)
    connection: Connection
    permissions: list[str] = Field(min_length=1)
    references: list[str] = []
    parameters: dict[str, ParameterSpec] = {}

    @field_validator("entrypoint")
    @classmethod
    def _entrypoint_relative(cls, value: str) -> str:
        return _check_relative_path(value)

    @field_validator("files")
    @classmethod
    def _files_valid(cls, value: dict[str, str]) -> dict[str, str]:
        for path, digest in value.items():
            _check_relative_path(path)
            if not _SHA256_HEX.match(digest):
                raise ValueError(f"hash for {path!r} must be 64 lowercase hex characters")
        return value

    @model_validator(mode="after")
    def _entrypoint_hashed(self) -> "PluginManifest":
        if self.entrypoint not in self.files:
            raise ValueError(f"entrypoint {self.entrypoint!r} must be listed in files")
        return self


def _resolve_inside(plugin_dir: Path, relative: str) -> Path:
    try:
        root = plugin_dir.resolve()
        resolved = (plugin_dir / relative).resolve()
    except (OSError, ValueError) as exc:
        raise ManifestError(f"{plugin_dir.name}: cannot resolve path {relative!r}: {exc}") from exc
    if not resolved.is_relative_to(root):
        raise ManifestError(f"{plugin_dir.name}: path {relative!r} resolves outside the plugin dir")
    return resolved


def load_manifest(plugin_dir: Path) -> PluginManifest:
    """Parse and validate ``plugin_dir/plugin.yaml``."""
    name = plugin_dir.name
    try:
        data = (plugin_dir / "plugin.yaml").read_bytes()
        if len(data) > _MAX_MANIFEST_BYTES:
            raise ManifestError(f"{name}: plugin.yaml exceeds {_MAX_MANIFEST_BYTES} bytes")
        raw = yaml.safe_load(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise ManifestError(f"{name}: cannot read plugin.yaml: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"{name}: plugin.yaml must be a mapping")
    try:
        manifest = PluginManifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestError(f"{name}: invalid plugin.yaml: {exc}") from exc
    for relative in manifest.files:
        _resolve_inside(plugin_dir, relative)
    return manifest


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_hashes(plugin_dir: Path, files: list[str]) -> dict[str, str]:
    """sha256 (hex) of each relative file, read in binary."""
    return {relative: _sha256(_resolve_inside(plugin_dir, relative)) for relative in files}


def verify_integrity(plugin_dir: Path, manifest: PluginManifest) -> None:
    """Raise IntegrityError if any hashed file is missing or modified."""
    for relative, expected in manifest.files.items():
        try:
            path = _resolve_inside(plugin_dir, relative)
        except ManifestError as exc:
            raise IntegrityError(str(exc)) from exc
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise IntegrityError(f"{plugin_dir.name}: cannot read {relative!r}: {exc}") from exc
        if hashlib.sha256(data).hexdigest() != expected:
            raise IntegrityError(
                f"{plugin_dir.name}: file {relative!r} was modified (hash mismatch)"
            )

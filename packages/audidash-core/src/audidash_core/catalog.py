"""Ed25519-signed plugin catalog and trust-tier assignment."""

import base64
import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audidash_core.manifest import (
    IntegrityError,
    ManifestError,
    PluginManifest,
    read_manifest,
    verify_integrity,
)

logger = logging.getLogger(__name__)

INDEX_NAME = "index.json"
SIGNATURE_NAME = "index.sig"


class Trust(StrEnum):
    official = "official"
    verified = "verified"
    community = "community"


@dataclass(frozen=True)
class CatalogEntry:
    manifest: PluginManifest
    path: Path
    trust: Trust
    # sha256 of the exact plugin.yaml bytes ``manifest`` was parsed from (the review pin).
    manifest_sha256: str


def _b64_file(path: Path) -> bytes:
    """Strict base64 decode of an ASCII text file; raises ValueError on bad content."""
    return base64.b64decode(path.read_bytes().decode("ascii").strip(), validate=True)


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load a raw 32-byte Ed25519 public key stored as base64 text."""
    return Ed25519PublicKey.from_public_bytes(_b64_file(path))


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an unencrypted PKCS8 PEM Ed25519 private key."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def _plugin_dirs(plugins_dir: Path) -> list[Path]:
    try:
        children = list(plugins_dir.iterdir())
    except OSError as exc:
        logger.warning("cannot list plugins dir %s: %s", plugins_dir, exc)
        return []
    return sorted(p for p in children if p.is_dir() and (p / "plugin.yaml").is_file())


def build_index(plugins_dir: Path) -> bytes:
    """Canonical JSON of ``{id: {"version", "files", "manifest"}}`` for all valid plugins.

    ``manifest`` is the sha256 of plugin.yaml bytes, so the signature covers the whole
    manifest (entrypoint, runtime, permissions...). Duplicate ids raise ValueError.
    """
    index: dict[str, dict[str, object]] = {}
    for plugin_dir in _plugin_dirs(plugins_dir):
        try:
            manifest, digest = read_manifest(plugin_dir)
        except ManifestError as exc:
            logger.warning("skipping %s: %s", plugin_dir.name, exc)
            continue
        if manifest.id in index:
            raise ValueError(f"duplicate plugin id {manifest.id!r} ({plugin_dir.name})")
        index[manifest.id] = {
            "version": manifest.version,
            "files": manifest.files,
            "manifest": digest,
        }
    return json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_index(index: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Raw 64-byte Ed25519 signature of the index bytes."""
    return private_key.sign(index)


def verify_index(index: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, index)
    except InvalidSignature:
        return False
    return True


def _load_signed_index(
    plugins_dir: Path, public_key: Ed25519PublicKey | None
) -> dict[str, object] | None:
    """Return the parsed index only if index.json verifies against index.sig."""
    if public_key is None:
        return None
    try:
        index_bytes = (plugins_dir / INDEX_NAME).read_bytes()
        signature = base64.b64decode(
            (plugins_dir / SIGNATURE_NAME).read_bytes().decode("ascii").strip(), validate=True
        )
    except ValueError:  # UnicodeDecodeError and binascii.Error are ValueErrors
        return None
    except OSError:
        return None
    if not verify_index(index_bytes, signature, public_key):
        logger.warning("catalog index signature is invalid; treating plugins as unsigned")
        return None
    try:
        parsed = json.loads(index_bytes)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _intact(plugin_dir: Path, manifest: PluginManifest) -> bool:
    try:
        verify_integrity(plugin_dir, manifest)
    except IntegrityError:
        return False
    return True


def _is_official(
    plugin_dir: Path, manifest: PluginManifest, digest: str, index: dict[str, object] | None
) -> bool:
    if index is None:
        return False
    entry = index.get(manifest.id)
    if not isinstance(entry, dict):
        return False
    if entry.get("version") != manifest.version or entry.get("files") != manifest.files:
        return False
    return entry.get("manifest") == digest and _intact(plugin_dir, manifest)


def _is_verified(
    plugin_dir: Path, manifest: PluginManifest, digest: str, verified_hashes: set[str]
) -> bool:
    """plugin.yaml's sha256 is allow-listed and every hashed file still matches it."""
    return digest in verified_hashes and _intact(plugin_dir, manifest)


def load_catalog(
    plugins_dir: Path,
    public_key: Ed25519PublicKey | None,
    verified_hashes: set[str] | frozenset[str] = frozenset(),
) -> list[CatalogEntry]:
    """Discover plugins and assign a trust tier to each, sorted by plugin id."""
    if not plugins_dir.is_dir():
        logger.warning("plugins dir %s does not exist", plugins_dir)
        return []
    index = _load_signed_index(plugins_dir, public_key)
    entries: list[CatalogEntry] = []
    for plugin_dir in _plugin_dirs(plugins_dir):
        try:
            manifest, digest = read_manifest(plugin_dir)
        except ManifestError as exc:
            logger.warning("skipping plugin %s: %s", plugin_dir.name, exc)
            continue
        if _is_official(plugin_dir, manifest, digest, index):
            trust = Trust.official
        elif _is_verified(plugin_dir, manifest, digest, set(verified_hashes)):
            trust = Trust.verified
        else:
            trust = Trust.community
        entries.append(
            CatalogEntry(manifest=manifest, path=plugin_dir, trust=trust, manifest_sha256=digest)
        )
    return sorted(entries, key=lambda e: e.manifest.id)

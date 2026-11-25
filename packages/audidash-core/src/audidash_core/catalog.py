"""Ed25519-signed plugin catalog and trust-tier assignment."""

import base64
import binascii
import hashlib
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
    load_manifest,
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


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load a raw 32-byte Ed25519 public key stored as base64 text."""
    return Ed25519PublicKey.from_public_bytes(
        base64.b64decode(path.read_text().strip(), validate=True)
    )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an unencrypted PKCS8 PEM Ed25519 private key."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def _plugin_dirs(plugins_dir: Path) -> list[Path]:
    return sorted(p for p in plugins_dir.iterdir() if p.is_dir() and (p / "plugin.yaml").is_file())


def build_index(plugins_dir: Path) -> bytes:
    """Canonical JSON of ``{plugin_id: {"version", "files"}}`` for all valid plugins."""
    index: dict[str, dict[str, object]] = {}
    for plugin_dir in _plugin_dirs(plugins_dir):
        try:
            manifest = load_manifest(plugin_dir)
        except ManifestError as exc:
            logger.warning("skipping %s: %s", plugin_dir.name, exc)
            continue
        index[manifest.id] = {"version": manifest.version, "files": manifest.files}
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
            (plugins_dir / SIGNATURE_NAME).read_text().strip(), validate=True
        )
    except (OSError, UnicodeDecodeError, binascii.Error):
        return None
    if not verify_index(index_bytes, signature, public_key):
        logger.warning("catalog index signature is invalid; treating plugins as unsigned")
        return None
    try:
        parsed = json.loads(index_bytes)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_official(
    plugin_dir: Path, manifest: PluginManifest, index: dict[str, object] | None
) -> bool:
    if index is None:
        return False
    entry = index.get(manifest.id)
    if not isinstance(entry, dict):
        return False
    if entry.get("version") != manifest.version or entry.get("files") != manifest.files:
        return False
    try:
        verify_integrity(plugin_dir, manifest)
    except IntegrityError:
        return False
    return True


def _is_verified(plugin_dir: Path, manifest: PluginManifest, verified_hashes: set[str]) -> bool:
    try:
        digest = hashlib.sha256((plugin_dir / manifest.entrypoint).read_bytes()).hexdigest()
    except OSError:
        return False
    return digest in verified_hashes


def load_catalog(
    plugins_dir: Path,
    public_key: Ed25519PublicKey | None,
    verified_hashes: set[str] | frozenset[str] = frozenset(),
) -> list[CatalogEntry]:
    """Discover plugins and assign a trust tier to each, sorted by plugin id."""
    index = _load_signed_index(plugins_dir, public_key)
    entries: list[CatalogEntry] = []
    for plugin_dir in _plugin_dirs(plugins_dir):
        try:
            manifest = load_manifest(plugin_dir)
        except ManifestError as exc:
            logger.warning("skipping plugin %s: %s", plugin_dir.name, exc)
            continue
        if _is_official(plugin_dir, manifest, index):
            trust = Trust.official
        elif _is_verified(plugin_dir, manifest, set(verified_hashes)):
            trust = Trust.verified
        else:
            trust = Trust.community
        entries.append(CatalogEntry(manifest=manifest, path=plugin_dir, trust=trust))
    return sorted(entries, key=lambda e: e.manifest.id)

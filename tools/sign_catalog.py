"""Maintainer tool: generate the catalog key pair and sign the plugin index.

Run offline. The private key must never be committed or stored in the repo.
"""

import argparse
import base64
import os
import sys
from pathlib import Path

from audidash_core.catalog import (
    INDEX_NAME,
    SIGNATURE_NAME,
    build_index,
    load_private_key,
    sign_index,
)
from audidash_core.manifest import IntegrityError, ManifestError, load_manifest, verify_integrity
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keygen(private_out: Path, public_out: Path) -> int:
    for path in (private_out, public_out):
        if path.exists():
            print(f"error: refusing to overwrite existing file {path}", file=sys.stderr)
            return 1
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    raw_public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    try:
        fd = os.open(private_out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        fd = os.open(public_out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(base64.b64encode(raw_public))
    except FileExistsError as exc:
        print(f"error: refusing to overwrite existing file {exc.filename}", file=sys.stderr)
        return 1
    print(f"private key: {private_out}\npublic key:  {public_out}")
    print(
        "WARNING: keep the private key offline and NEVER commit it to the repository.",
        file=sys.stderr,
    )
    return 0


def _sign(plugins_dir: Path, private_key_path: Path) -> int:
    key = load_private_key(private_key_path)
    for plugin_dir in sorted(p for p in plugins_dir.iterdir() if (p / "plugin.yaml").is_file()):
        try:
            verify_integrity(plugin_dir, load_manifest(plugin_dir))
        except (ManifestError, IntegrityError) as exc:
            print(f"error: plugin {plugin_dir.name} is not signable: {exc}", file=sys.stderr)
            return 1
    try:
        index = build_index(plugins_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    (plugins_dir / INDEX_NAME).write_bytes(index)
    (plugins_dir / SIGNATURE_NAME).write_bytes(base64.b64encode(sign_index(index, key)))
    print(f"wrote {plugins_dir / INDEX_NAME} and {plugins_dir / SIGNATURE_NAME}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="generate an Ed25519 key pair")
    keygen.add_argument("--private-out", type=Path, required=True)
    keygen.add_argument("--public-out", type=Path, required=True)
    sign = sub.add_parser("sign", help="write index.json and index.sig")
    sign.add_argument("--plugins-dir", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "keygen":
        return _keygen(args.private_out, args.public_out)
    return _sign(args.plugins_dir, args.private_key)


if __name__ == "__main__":
    sys.exit(main())

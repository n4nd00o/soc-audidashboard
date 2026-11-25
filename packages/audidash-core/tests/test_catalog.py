import base64
import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from audidash_core.catalog import (
    Trust,
    build_index,
    load_catalog,
    load_private_key,
    load_public_key,
    sign_index,
    verify_index,
)
from audidash_core.manifest import compute_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGN_TOOL = Path(__file__).resolve().parents[3] / "tools" / "sign_catalog.py"


def make_plugin(
    plugins_dir: Path, plugin_id: str = "demo-plugin", body: bytes = b"print(1)\n"
) -> Path:
    plugin_dir = plugins_dir / plugin_id
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "run.py").write_bytes(body)
    data: dict[str, Any] = {
        "id": plugin_id,
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
    (plugin_dir / "plugin.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return plugin_dir


def write_signed_index(plugins_dir: Path, key: Ed25519PrivateKey) -> None:
    index = build_index(plugins_dir)
    (plugins_dir / "index.json").write_bytes(index)
    signature = base64.b64encode(sign_index(index, key))
    (plugins_dir / "index.sig").write_bytes(signature)


def test_official_when_signed(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    make_plugin(tmp_path)
    write_signed_index(tmp_path, key)
    entries = load_catalog(tmp_path, key.public_key())
    assert [(e.manifest.id, e.trust) for e in entries] == [("demo-plugin", Trust.official)]
    assert entries[0].path == tmp_path / "demo-plugin"


def test_community_when_signature_invalid(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    make_plugin(tmp_path)
    write_signed_index(tmp_path, Ed25519PrivateKey.generate())
    entries = load_catalog(tmp_path, key.public_key())
    assert [e.trust for e in entries] == [Trust.community]


def test_community_without_public_key_or_index(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    make_plugin(tmp_path)
    assert [e.trust for e in load_catalog(tmp_path, key.public_key())] == [Trust.community]
    write_signed_index(tmp_path, key)
    assert [e.trust for e in load_catalog(tmp_path, None)] == [Trust.community]


def test_community_when_plugin_changed_after_signing(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    plugin_dir = make_plugin(tmp_path)
    write_signed_index(tmp_path, key)
    (plugin_dir / "run.py").write_bytes(b"print('evil')\n")
    entries = load_catalog(tmp_path, key.public_key())
    assert [e.trust for e in entries] == [Trust.community]


def test_community_when_manifest_differs_from_index(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    plugin_dir = make_plugin(tmp_path)
    write_signed_index(tmp_path, key)
    # Self-consistent re-hash of the plugin: integrity passes but index no longer matches.
    (plugin_dir / "run.py").write_bytes(b"print('new')\n")
    data = yaml.safe_load((plugin_dir / "plugin.yaml").read_text(encoding="utf-8"))
    data["files"] = compute_hashes(plugin_dir, ["run.py"])
    (plugin_dir / "plugin.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    entries = load_catalog(tmp_path, key.public_key())
    assert [e.trust for e in entries] == [Trust.community]


def test_community_when_plugin_not_in_index(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    make_plugin(tmp_path)
    write_signed_index(tmp_path, key)
    make_plugin(tmp_path, "other-plugin")
    trust = {e.manifest.id: e.trust for e in load_catalog(tmp_path, key.public_key())}
    assert trust == {"demo-plugin": Trust.official, "other-plugin": Trust.community}


def test_verified_by_hash_allowlist(tmp_path: Path) -> None:
    body = b"print('allowed')\n"
    make_plugin(tmp_path, body=body)
    allowed = {hashlib.sha256(body).hexdigest()}
    entries = load_catalog(tmp_path, None, allowed)
    assert [e.trust for e in entries] == [Trust.verified]
    assert [e.trust for e in load_catalog(tmp_path, None, {"0" * 64})] == [Trust.community]


def test_bad_manifest_skipped(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    make_plugin(tmp_path)
    broken = tmp_path / "broken-plugin"
    broken.mkdir()
    (broken / "plugin.yaml").write_text("not: [valid", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    with caplog.at_level("WARNING"):
        entries = load_catalog(tmp_path, None)
    assert [e.manifest.id for e in entries] == ["demo-plugin"]
    assert "broken-plugin" in caplog.text


def test_entries_sorted_by_id(tmp_path: Path) -> None:
    make_plugin(tmp_path, "zeta-plugin")
    make_plugin(tmp_path, "alpha-plugin")
    assert [e.manifest.id for e in load_catalog(tmp_path, None)] == ["alpha-plugin", "zeta-plugin"]


def test_verify_index_roundtrip_and_tamper() -> None:
    key = Ed25519PrivateKey.generate()
    sig = sign_index(b"{}", key)
    assert verify_index(b"{}", sig, key.public_key())
    assert not verify_index(b"{ }", sig, key.public_key())
    assert not verify_index(b"{}", b"short", key.public_key())


def test_build_index_is_canonical(tmp_path: Path) -> None:
    make_plugin(tmp_path)
    index = build_index(tmp_path)
    assert b" " not in index and index.startswith(b'{"demo-plugin":')
    assert index == build_index(tmp_path)


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sign_catalog", SIGN_TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sign_tool_end_to_end(tmp_path: Path) -> None:
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    make_plugin(plugins)
    priv, pub = tmp_path / "k" / "catalog.pem", tmp_path / "k" / "catalog.pub"
    priv.parent.mkdir()
    base = [sys.executable, str(SIGN_TOOL)]
    keygen = subprocess.run(  # noqa: S603
        [*base, "keygen", "--private-out", str(priv), "--public-out", str(pub)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "offline" in (keygen.stdout + keygen.stderr).lower()
    again = subprocess.run(  # noqa: S603
        [*base, "keygen", "--private-out", str(priv), "--public-out", str(pub)],
        capture_output=True,
        text=True,
    )
    assert again.returncode != 0
    subprocess.run(  # noqa: S603
        [*base, "sign", "--plugins-dir", str(plugins), "--private-key", str(priv)],
        check=True,
        capture_output=True,
    )
    assert (plugins / "index.json").is_file() and (plugins / "index.sig").is_file()
    entries = load_catalog(plugins, load_public_key(pub))
    assert [e.trust for e in entries] == [Trust.official]


def test_sign_tool_main_importable(tmp_path: Path) -> None:
    tool = _load_tool()
    priv, pub = tmp_path / "a.pem", tmp_path / "a.pub"
    assert tool.main(["keygen", "--private-out", str(priv), "--public-out", str(pub)]) == 0
    key = load_private_key(priv)
    assert isinstance(key, Ed25519PrivateKey)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64decode(pub.read_text()) == raw

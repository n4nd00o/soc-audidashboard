import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from audidash_core.manifest import (
    IntegrityError,
    ManifestError,
    PluginManifest,
    compute_hashes,
    load_manifest,
    verify_integrity,
)


def make_plugin(tmp_path: Path, **overrides: Any) -> Path:
    plugin_dir = tmp_path / "demo-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "run.py").write_bytes(b"print('ok')\n")
    data: dict[str, Any] = {
        "id": "demo-plugin",
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
    data.update(overrides)
    (plugin_dir / "plugin.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return plugin_dir


def test_loads_valid_manifest(tmp_path: Path) -> None:
    manifest = load_manifest(make_plugin(tmp_path))
    assert isinstance(manifest, PluginManifest)
    assert manifest.id == "demo-plugin"
    assert manifest.entrypoint == "run.py"
    assert manifest.references == []
    assert manifest.parameters == {}


def test_rejects_trust_field(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="demo-plugin"):
        load_manifest(make_plugin(tmp_path, trust="official"))


def test_rejects_unknown_runtime(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="runtime"):
        load_manifest(make_plugin(tmp_path, runtime="ruby"))


def test_rejects_invalid_yaml(tmp_path: Path) -> None:
    plugin_dir = make_plugin(tmp_path)
    (plugin_dir / "plugin.yaml").write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(ManifestError, match="demo-plugin"):
        load_manifest(plugin_dir)


def test_rejects_missing_manifest(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "empty-plugin"
    plugin_dir.mkdir()
    with pytest.raises(ManifestError, match="empty-plugin"):
        load_manifest(plugin_dir)


def test_rejects_bad_hash_format(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="64 lowercase hex"):
        load_manifest(make_plugin(tmp_path, files={"run.py": "ABC"}))


@pytest.mark.parametrize(
    "bad_path",
    ["../evil.py", "/etc/passwd", r"C:\x.py", "C:/x.py", r"sub\run.py", "a/../../evil.py"],
)
def test_rejects_path_escape(tmp_path: Path, bad_path: str) -> None:
    digest = "0" * 64
    with pytest.raises(ManifestError):
        load_manifest(make_plugin(tmp_path, entrypoint=bad_path, files={bad_path: digest}))


def test_rejects_path_escape_in_files_key(tmp_path: Path) -> None:
    plugin_dir_files = {"../evil.py": "0" * 64}
    with pytest.raises(ManifestError):
        load_manifest(make_plugin(tmp_path, files={"run.py": "0" * 64, **plugin_dir_files}))


def test_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("print('evil')\n", encoding="utf-8")
    plugin_dir = make_plugin(tmp_path)
    link = plugin_dir / "link.py"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")
    _rewrite(plugin_dir, entrypoint="link.py", files={"link.py": "0" * 64})
    with pytest.raises(ManifestError):
        load_manifest(plugin_dir)


def test_entrypoint_must_be_hashed(tmp_path: Path) -> None:
    plugin_dir = make_plugin(tmp_path)
    (plugin_dir / "other.py").write_text("x = 1\n", encoding="utf-8")
    _rewrite(plugin_dir, files=compute_hashes(plugin_dir, ["other.py"]))
    with pytest.raises(ManifestError, match="entrypoint"):
        load_manifest(plugin_dir)


def _rewrite(plugin_dir: Path, **changes: Any) -> Path:
    path = plugin_dir / "plugin.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data.update(changes)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return plugin_dir


def test_integrity_ok(tmp_path: Path) -> None:
    plugin_dir = make_plugin(tmp_path)
    verify_integrity(plugin_dir, load_manifest(plugin_dir))


def test_integrity_tampered(tmp_path: Path) -> None:
    plugin_dir = make_plugin(tmp_path)
    manifest = load_manifest(plugin_dir)
    (plugin_dir / "run.py").write_bytes(b"print('0k')\n")
    with pytest.raises(IntegrityError, match=r"run\.py"):
        verify_integrity(plugin_dir, manifest)


def test_integrity_missing_file(tmp_path: Path) -> None:
    plugin_dir = make_plugin(tmp_path)
    manifest = load_manifest(plugin_dir)
    (plugin_dir / "run.py").unlink()
    with pytest.raises(IntegrityError, match=r"run\.py"):
        verify_integrity(plugin_dir, manifest)


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are Windows-only")
def test_rejects_junction_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_bytes(b"print('evil')")
    plugin_dir = make_plugin(tmp_path)
    junction = plugin_dir / "linked"
    result = subprocess.run(  # noqa: S603
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("cannot create directory junction")
    _rewrite(plugin_dir, entrypoint="linked/evil.py", files={"linked/evil.py": "0" * 64})
    with pytest.raises(ManifestError):
        load_manifest(plugin_dir)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (bytes([255, 254, 0]) + b"bad", "plugin.yaml"),
        (b"[" * 5000, "plugin.yaml"),
        (b"# " + b"x" * (256 * 1024), "exceeds"),
        (b"", "mapping"),
        (b"just a string", "mapping"),
    ],
)
def test_rejects_bad_manifest_content(tmp_path: Path, content: bytes, message: str) -> None:
    plugin_dir = make_plugin(tmp_path)
    (plugin_dir / "plugin.yaml").write_bytes(content)
    with pytest.raises(ManifestError, match=message):
        load_manifest(plugin_dir)


def test_integrity_unreadable_path(tmp_path: Path) -> None:
    plugin_dir = make_plugin(tmp_path)
    manifest = load_manifest(plugin_dir)
    (plugin_dir / "run.py").unlink()
    (plugin_dir / "run.py").mkdir()
    with pytest.raises(IntegrityError, match="run"):
        verify_integrity(plugin_dir, manifest)

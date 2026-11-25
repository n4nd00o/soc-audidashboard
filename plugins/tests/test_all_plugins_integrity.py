from pathlib import Path

import pytest
from audidash_core.manifest import load_manifest, verify_integrity

PLUGINS_DIR = Path(__file__).resolve().parent.parent
PLUGIN_DIRS = sorted(p.parent for p in PLUGINS_DIR.glob("*/plugin.yaml"))


def test_plugins_exist() -> None:
    assert len(PLUGIN_DIRS) >= 3


@pytest.mark.parametrize("plugin_dir", PLUGIN_DIRS, ids=lambda p: p.name)
def test_all_plugins_integrity(plugin_dir: Path) -> None:
    manifest = load_manifest(plugin_dir)
    assert manifest.id == plugin_dir.name
    verify_integrity(plugin_dir, manifest)

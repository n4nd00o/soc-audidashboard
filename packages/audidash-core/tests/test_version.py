import tomllib
from importlib.metadata import version
from pathlib import Path

import audidash_core

RELEASE = "0.2.0a1"
REPO = Path(__file__).resolve().parents[3]


def test_version() -> None:
    assert audidash_core.__version__ == RELEASE
    assert version("audidash-core") == RELEASE


def test_workspace_versions_move_together() -> None:
    projects = [
        REPO / "pyproject.toml",
        *sorted((REPO / "packages").glob("*/pyproject.toml")),
    ]
    found = {
        path.parent.name: tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"]
        for path in projects
    }
    assert set(found.values()) == {RELEASE}, found
    assert len(found) == 4

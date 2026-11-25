from pathlib import Path

import pytest
from audidash_server.app import create_app
from audidash_server.settings import Settings
from fastapi.testclient import TestClient


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return Settings(
        dev_mode=True,
        data_dir=data_dir,
        database_url=f"sqlite:///{(tmp_path / 'audidash.db').as_posix()}",
    )


@pytest.fixture
def app_client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), base_url="https://testserver")

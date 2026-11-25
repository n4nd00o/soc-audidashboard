from collections.abc import Iterator
from pathlib import Path

import pytest
from audidash_server.app import create_app
from audidash_server.db import init_db, make_engine
from audidash_server.settings import Settings
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session as DbSession


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


@pytest.fixture
def prod_settings(settings: Settings) -> Settings:
    good = SecretStr("p" * 32)
    return settings.model_copy(
        update={
            "dev_mode": False,
            "secret_key": good,
            "proxy_secret": good,
            "ca_passphrase": good,
        }
    )


@pytest.fixture
def db_session(settings: Settings) -> Iterator[DbSession]:
    engine = make_engine(settings.database_url)
    init_db(engine)
    with DbSession(engine) as session:
        yield session
    engine.dispose()

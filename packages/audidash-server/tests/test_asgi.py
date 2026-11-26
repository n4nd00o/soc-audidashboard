from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def test_app_factory_reads_settings_from_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from audidash_server.asgi import app_factory

    monkeypatch.setenv("AUDIDASH_DEV_MODE", "true")
    monkeypatch.setenv("AUDIDASH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIDASH_DATABASE_URL", f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    app = app_factory()
    assert app.state.settings.data_dir == tmp_path
    response = TestClient(app, base_url="https://testserver").get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_app_factory_refuses_missing_production_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from audidash_server.asgi import app_factory

    for name in ("DEV_MODE", "SECRET_KEY", "PROXY_SECRET", "CA_PASSPHRASE", "DATABASE_URL"):
        monkeypatch.delenv(f"AUDIDASH_{name}", raising=False)
    with pytest.raises(ValueError, match="AUDIDASH_SECRET_KEY is missing"):
        app_factory()

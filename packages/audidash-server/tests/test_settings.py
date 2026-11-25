import pytest
from audidash_server.settings import Settings
from pydantic import SecretStr

GOOD = "x" * 32


def _prod(
    secret_key: str = GOOD,
    proxy_secret: str = GOOD,
    ca_passphrase: str = GOOD,
) -> Settings:
    return Settings(
        dev_mode=False,
        database_url="sqlite:///x.db",
        secret_key=SecretStr(secret_key),
        proxy_secret=SecretStr(proxy_secret),
        ca_passphrase=SecretStr(ca_passphrase),
    )


def test_production_accepts_valid_secrets() -> None:
    _prod().validate_for_production()


def test_production_requires_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SECRET_KEY", "PROXY_SECRET", "CA_PASSPHRASE", "DATABASE_URL"):
        monkeypatch.delenv(f"AUDIDASH_{name}", raising=False)
    with pytest.raises(ValueError, match="AUDIDASH_PROXY_SECRET"):
        Settings(dev_mode=False, secret_key=GOOD, ca_passphrase=GOOD).validate_for_production()


def test_production_rejects_short_secret() -> None:
    short = "y" * 31
    with pytest.raises(ValueError, match="AUDIDASH_SECRET_KEY") as exc:
        _prod(secret_key=short).validate_for_production()
    assert short not in str(exc.value)


def test_production_requires_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDIDASH_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="AUDIDASH_DATABASE_URL"):
        Settings(
            dev_mode=False, secret_key=GOOD, proxy_secret=GOOD, ca_passphrase=GOOD
        ).validate_for_production()


def test_dev_mode_generates_random_secrets() -> None:
    a = Settings(dev_mode=True)
    b = Settings(dev_mode=True)
    for s in (a, b):
        assert len(s.secret_key.get_secret_value()) >= 32
        assert len(s.proxy_secret.get_secret_value()) >= 32
        assert len(s.ca_passphrase.get_secret_value()) >= 32
    assert a.secret_key.get_secret_value() != b.secret_key.get_secret_value()


def test_dev_mode_does_not_log_secret_values(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        s = Settings(dev_mode=True)
    assert caplog.records
    assert s.secret_key.get_secret_value() not in caplog.text


def test_env_prefix_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIDASH_DEV_MODE", "true")
    monkeypatch.setenv("AUDIDASH_RETENTION_DAYS", "30")
    s = Settings()
    assert s.dev_mode is True
    assert s.retention_days == 30
    assert s.session_idle_minutes == 30
    assert s.session_absolute_hours == 12

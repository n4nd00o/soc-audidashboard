"""Server settings loaded from the environment (prefix ``AUDIDASH_``)."""

from __future__ import annotations

import logging
import secrets
from pathlib import Path
from typing import Any

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

MIN_SECRET_LENGTH = 32
_SECRET_FIELDS = ("secret_key", "proxy_secret", "ca_passphrase")


class Settings(BaseSettings):
    """Runtime configuration. Secrets come only from env / Docker secrets."""

    model_config = SettingsConfigDict(env_prefix="AUDIDASH_", extra="ignore")

    database_url: str = ""
    secret_key: SecretStr = SecretStr("")
    proxy_secret: SecretStr = SecretStr("")
    ca_passphrase: SecretStr = SecretStr("")
    dev_mode: bool = False
    data_dir: Path = Path("./data")
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    retention_days: int = 365

    @model_validator(mode="before")
    @classmethod
    def _fill_dev_secrets(cls, values: Any) -> Any:
        """In dev mode replace missing secrets with random per-process values."""
        if not isinstance(values, dict) or not _is_dev(values):
            return values
        for name in _SECRET_FIELDS:
            if not _has_value(values.get(name)):
                values[name] = secrets.token_urlsafe(48)
                logger.warning(
                    "AUDIDASH_%s not set: using a random per-process value (dev mode)",
                    name.upper(),
                )
        return values

    def validate_for_production(self) -> None:
        """Raise ValueError naming every missing or too-short secret (never its value)."""
        if self.dev_mode:
            return
        problems: list[str] = []
        if not self.database_url:
            problems.append("AUDIDASH_DATABASE_URL is missing")
        for name in _SECRET_FIELDS:
            value = getattr(self, name).get_secret_value()
            env = f"AUDIDASH_{name.upper()}"
            if not value:
                problems.append(f"{env} is missing")
            elif len(value) < MIN_SECRET_LENGTH:
                problems.append(f"{env} is shorter than {MIN_SECRET_LENGTH} characters")
        if problems:
            raise ValueError("Invalid production configuration: " + "; ".join(problems))


def _has_value(value: object) -> bool:
    if isinstance(value, SecretStr):
        return bool(value.get_secret_value())
    return bool(value)


def _is_dev(values: dict[str, Any]) -> bool:
    raw = values.get("dev_mode")
    return raw is True or (isinstance(raw, str) and raw.strip().lower() in {"1", "true", "yes"})

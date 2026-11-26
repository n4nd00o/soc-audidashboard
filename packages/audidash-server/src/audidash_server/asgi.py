"""ASGI entry point for ``uvicorn --factory audidash_server.asgi:app_factory``."""

from __future__ import annotations

from fastapi import FastAPI

from audidash_server.app import create_app
from audidash_server.settings import Settings


def app_factory() -> FastAPI:
    """Build the app from ``AUDIDASH_*`` environment variables (fails fast on bad config)."""
    return create_app(Settings())

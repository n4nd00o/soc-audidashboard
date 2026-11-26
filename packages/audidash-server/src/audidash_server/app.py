"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

import jinja2
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.types import ASGIApp

from audidash_server import __version__
from audidash_server.auth.passwords import dummy_hash
from audidash_server.auth.ratelimit import LoginRateLimiter
from audidash_server.auth.routes import router as auth_router
from audidash_server.auth.sessions import NotAuthenticated, not_authenticated_handler
from audidash_server.db import init_db, make_engine, make_sessionmaker
from audidash_server.security_headers import SecurityHeadersMiddleware
from audidash_server.settings import Settings

PACKAGE_DIR = Path(__file__).parent
STATIC_DIR = PACKAGE_DIR / "static"
TEMPLATES_DIR = PACKAGE_DIR / "templates"


class _OutermostHeadersFastAPI(FastAPI):
    """FastAPI whose security-headers layer wraps ServerErrorMiddleware too (covers 500s)."""

    def build_middleware_stack(self) -> ASGIApp:
        return SecurityHeadersMiddleware(super().build_middleware_stack())


def create_app(settings: Settings) -> FastAPI:
    docs = settings.dev_mode
    if not settings.dev_mode:
        settings.validate_for_production()
    app = _OutermostHeadersFastAPI(
        title="SOC AudiDashboard",
        version=__version__,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    engine = make_engine(settings.database_url)
    if settings.dev_mode and settings.database_url.startswith("sqlite"):
        init_db(engine)  # dev convenience; production schema comes from Alembic only
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES_DIR), autoescape=True, enable_async=False
    )
    app.state.templates = Jinja2Templates(env=env)
    app.state.login_limiter = LoginRateLimiter()
    dummy_hash()  # precompute so the first unknown-user login is not measurably slower
    app.add_exception_handler(NotAuthenticated, not_authenticated_handler)
    app.include_router(auth_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app

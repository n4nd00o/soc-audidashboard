"""Dashboard overview page (`GET /`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session as DbSession
from starlette.responses import Response

from audidash_server import clock
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Session, User
from audidash_server.web import queries
from audidash_server.web.layout import page_context

router = APIRouter()


@router.get("/")
def overview(
    request: Request,
    db: Annotated[DbSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
    sess: Annotated[Session, Depends(current_session)],
) -> Response:
    data = queries.build_overview(db, clock.now())
    context = page_context(
        user,
        sess,
        "overview",
        ov=data,
        band_labels=queries.BAND_LABELS,
        severity_labels=queries.SEVERITY_LABELS,
    )
    return render(request, "overview.html", context)

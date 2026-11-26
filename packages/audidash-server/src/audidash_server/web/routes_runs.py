"""Runs page: what was uploaded, by whom, from which device, and what it changed."""

from __future__ import annotations

from typing import Annotated

from audidash_core.runner import RunStatus
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session as DbSession
from starlette.responses import Response

from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Session, User
from audidash_server.web import run_queries as rq
from audidash_server.web.layout import page_context

router = APIRouter(prefix="/runs")

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    filters = rq.parse_run_filters(request.query_params)
    page = rq.list_runs(db, filters)
    assets, plugins = rq.run_filter_options(db)
    context = page_context(
        user,
        sess,
        "runs",
        page=page,
        filters=filters,
        filter_assets=assets,
        filter_plugins=plugins,
        statuses=list(RunStatus),
        status_labels=rq.STATUS_LABELS,
        trust_labels=rq.TRUST_LABELS,
    )
    return render(request, "runs/list.html", context)

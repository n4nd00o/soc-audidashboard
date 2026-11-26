"""Audit log viewer (admin only): paginated newest-first chain and an integrity check."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession
from starlette.responses import Response

from audidash_server import audit
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.rbac import require_role
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import AuditEntry, Device, Role, Session, User
from audidash_server.web.layout import page_context
from audidash_server.web.paging import PAGE_SIZE, page_count, parse_page

router = APIRouter(prefix="/audit", dependencies=[require_role(Role.admin), Depends(csrf_protect)])

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]


@dataclass(frozen=True)
class AuditRow:
    seq: int
    at: datetime
    actor: str
    action: str
    target: str | None
    details: str


@dataclass(frozen=True)
class AuditPage:
    rows: list[AuditRow]
    total: int
    page: int
    pages: int


def _actor(entry: AuditEntry, username: str | None, device_name: str | None) -> str:
    if entry.actor_user_id is not None:
        return username or str(entry.actor_user_id)
    if entry.actor_device_id is not None:
        return f"dispositivo: {device_name or entry.actor_device_id}"
    return "sistema"


def _list(db: DbSession, page: int) -> AuditPage:
    total = db.scalar(select(func.count()).select_from(AuditEntry)) or 0
    pages = page_count(total)
    page = min(page, pages)
    query = (
        select(AuditEntry, User.username, Device.name)
        .outerjoin(User, User.id == AuditEntry.actor_user_id)
        .outerjoin(Device, Device.id == AuditEntry.actor_device_id)
        .order_by(AuditEntry.seq.desc())
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    rows = [
        AuditRow(
            seq=int(entry.seq),
            at=entry.at,
            actor=_actor(entry, username, device_name),
            action=entry.action,
            target=entry.target,
            details=json.dumps(entry.details, ensure_ascii=False, sort_keys=True),
        )
        for entry, username, device_name in db.execute(query).all()
    ]
    return AuditPage(rows=rows, total=total, page=page, pages=pages)


def _render_page(
    request: Request, db: DbSession, user: User, sess: Session, page: int, **extra: Any
) -> Response:
    context = page_context(user, sess, "audit", page=_list(db, page), **extra)
    return render(request, "audit/list.html", context)


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    return _render_page(request, db, user, sess, parse_page(request.query_params.get("page")))


@router.post("/verify")
def verify(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    bad_seq = audit.verify_chain(db)
    return _render_page(request, db, user, sess, 1, verified=True, bad_seq=bad_seq)

"""Plugins page: manifests seen in uploaded runs and the verified allowlist (admin-managed)."""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession
from starlette.datastructures import FormData
from starlette.responses import RedirectResponse, Response

from audidash_server import audit, clock
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.rbac import require_role
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Role, Run, Session, User, VerifiedPlugin
from audidash_server.web import run_queries as rq
from audidash_server.web.forms import Form, form_text
from audidash_server.web.layout import page_context

router = APIRouter(prefix="/plugins")

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]
ADMIN = [require_role(Role.admin), Depends(csrf_protect)]

_SHA256 = re.compile(r"[0-9a-f]{64}")


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _digest(form: FormData) -> str:
    value = form_text(form, "manifest_sha256")
    if not _SHA256.fullmatch(value):
        raise HTTPException(status_code=422, detail="manifest_sha256 inválido")
    return value


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    allowlist = db.execute(
        select(VerifiedPlugin, User.username)
        .outerjoin(User, User.id == VerifiedPlugin.approved_by)
        .order_by(VerifiedPlugin.plugin_id, VerifiedPlugin.version)
    ).all()
    context = page_context(
        user,
        sess,
        "plugins",
        groups=rq.plugin_groups(db),
        allowlist=[(row, username) for row, username in allowlist],
        is_admin=user.role is Role.admin,
        trust_labels=rq.TRUST_LABELS,
    )
    return render(request, "plugins/list.html", context)


@router.post("/verify", dependencies=ADMIN)
def verify(db: Db, user: CurrentUser, form: Form) -> Response:
    digest = _digest(form)
    known = select(VerifiedPlugin.id).where(VerifiedPlugin.manifest_sha256 == digest)
    if db.scalars(known).first() is not None:
        return _see_other("/plugins")  # already on the allowlist: nothing to record
    seen = db.scalars(
        select(Run).where(Run.manifest_sha256 == digest).order_by(Run.received_at.desc()).limit(1)
    ).first()
    if seen is None:
        raise HTTPException(status_code=404, detail="Nenhuma execução usou este manifesto")
    db.add(
        VerifiedPlugin(
            manifest_sha256=digest,
            plugin_id=seen.plugin_id,
            version=seen.plugin_version,
            approved_by=user.id,
            approved_at=clock.now(),
        )
    )
    try:
        db.flush()
    except IntegrityError:  # a concurrent admin approved the same manifest
        db.rollback()
        return _see_other("/plugins")
    audit.record(
        db,
        action="plugin.verify",
        actor_user_id=user.id,
        actor_device_id=None,
        target=seen.plugin_id,
        details={
            "manifest_sha256": digest,
            "plugin_id": seen.plugin_id,
            "version": seen.plugin_version,
        },
    )
    db.commit()
    return _see_other("/plugins")


@router.post("/unverify", dependencies=ADMIN)
def unverify(db: Db, user: CurrentUser, form: Form) -> Response:
    digest = _digest(form)
    row = db.scalars(select(VerifiedPlugin).where(VerifiedPlugin.manifest_sha256 == digest)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Manifesto não está na lista de verificados")
    plugin_id, version = row.plugin_id, row.version
    db.delete(row)
    audit.record(
        db,
        action="plugin.unverify",
        actor_user_id=user.id,
        actor_device_id=None,
        target=plugin_id,
        details={"manifest_sha256": digest, "plugin_id": plugin_id, "version": version},
    )
    db.commit()
    return _see_other("/plugins")

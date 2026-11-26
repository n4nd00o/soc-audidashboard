"""Devices page: enrolled devices, enrolment tokens (shown once) and revocation (admin)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession
from starlette.responses import RedirectResponse, Response

from audidash_server import audit, clock
from audidash_server.api.deps import get_ca
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.rbac import require_role
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Device, Role, Session, User
from audidash_server.services.enrollment import ENROLLMENT_TOKEN_TTL, create_enrollment_token
from audidash_server.settings import Settings
from audidash_server.textguard import without_nul
from audidash_server.web import device_queries as dq
from audidash_server.web.forms import Form, form_text
from audidash_server.web.layout import page_context

router = APIRouter(prefix="/devices")

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]
ADMIN = [require_role(Role.admin), Depends(csrf_protect)]

URL_WARNING = (
    "Não foi possível derivar a URL do servidor a partir do cabeçalho Host: configure "
    "AUDIDASH_PUBLIC_DASHBOARD_URL e AUDIDASH_PUBLIC_API_URL e substitua <servidor> abaixo."
)
NAME_MESSAGE = (
    "Nome do dispositivo inválido: use de 1 a 128 caracteres entre letras, números, ponto, "
    "hífen, sublinhado e espaço (começando por letra ou número)."
)
STATE_LABELS = {"active": "Ativo", "revoked": "Revogado", "expired": "Certificado expirado"}
TOKEN_LABELS = {"unused": "Não usado", "used": "Usado", "expired": "Expirado"}


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _render_page(
    request: Request,
    db: DbSession,
    user: User,
    sess: Session,
    *,
    status_code: int = 200,
    **extra: Any,
) -> Response:
    is_admin = user.role is Role.admin
    context = page_context(
        user,
        sess,
        "devices",
        is_admin=is_admin,
        devices=dq.list_devices(db),
        tokens=dq.list_tokens(db) if is_admin else [],
        state_labels=STATE_LABELS,
        token_labels=TOKEN_LABELS,
        error=extra.pop("error", None),
        new_command=extra.pop("new_command", None),
        name_value=extra.pop("name_value", ""),
        **extra,
    )
    response = render(request, "devices/list.html", context, status_code=status_code)
    if context["new_command"]:
        response.headers["Cache-Control"] = "no-store"
    return response


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    return _render_page(request, db, user, sess)


@router.post("/tokens", dependencies=ADMIN)
def create_token(
    request: Request, db: Db, user: CurrentUser, sess: CurrentSession, form: Form
) -> Response:
    name = form_text(form, "name").strip()
    if not dq.DEVICE_NAME.fullmatch(name):
        return _render_page(
            request,
            db,
            user,
            sess,
            status_code=422,
            error=NAME_MESSAGE,
            name_value=without_nul(name)[:128],
        )
    settings: Settings = request.app.state.settings
    default_dashboard, default_api, derived_ok = dq.default_urls(str(request.base_url))
    ca_fingerprint = get_ca(request).fingerprint_sha256()  # fail before committing a token
    token = create_enrollment_token(db, user.id)
    expires_at = clock.now() + ENROLLMENT_TOKEN_TTL
    audit.record(
        db,
        action="enrollment_token.create",
        actor_user_id=user.id,
        actor_device_id=None,
        target=name,
        details={"device_name": name, "expires_at": expires_at.isoformat()},
    )
    db.commit()
    command = dq.enroll_command(
        dashboard_url=settings.public_dashboard_url or default_dashboard,
        api_url=settings.public_api_url or default_api,
        token=token,
        name=name,
        ca_fingerprint=ca_fingerprint,
    )
    url_warning = (
        None
        if derived_ok or (settings.public_dashboard_url and settings.public_api_url)
        else URL_WARNING
    )
    return _render_page(request, db, user, sess, new_command=command, url_warning=url_warning)


@router.post("/{device_id}/revoke", dependencies=ADMIN)
def revoke(device_id: uuid.UUID, db: Db, user: CurrentUser) -> Response:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    if device.revoked_at is None:
        device.revoked_at = clock.now()
        audit.record(
            db,
            action="device.revoke",
            actor_user_id=user.id,
            actor_device_id=None,
            target=str(device.id),
            details={"device_name": device.name},
        )
        db.commit()
    return _see_other("/devices")

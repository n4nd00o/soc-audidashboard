"""Users page (admin only): create with a temporary password, change role, disable/enable."""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession
from starlette.responses import RedirectResponse, Response

from audidash_server import audit, clock
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.passwords import WeakPasswordError, hash_password, validate_password
from audidash_server.auth.rbac import require_role
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Role, Session, User
from audidash_server.textguard import without_nul
from audidash_server.web.layout import page_context

router = APIRouter(prefix="/users", dependencies=[require_role(Role.admin), Depends(csrf_protect)])

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]

USERNAME = re.compile(r"[A-Za-z0-9_.-]{3,64}")
ROLE_LABELS = {Role.admin: "Administrador", Role.analyst: "Analista", Role.viewer: "Visualizador"}
USERNAME_MESSAGE = (
    "Usuário inválido: use de 3 a 64 caracteres entre letras, números, '_', '.' e '-'."
)
ROLE_MESSAGE = "Perfil inválido."
DUPLICATE_MESSAGE = "Já existe um usuário com esse nome."
SELF_MESSAGE = "Você não pode alterar o próprio perfil nem desativar a própria conta."
LAST_ADMIN_MESSAGE = "Deve restar pelo menos um administrador ativo."


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _render_page(
    request: Request,
    db: DbSession,
    user: User,
    sess: Session,
    *,
    status_code: int = 200,
    error: str | None = None,
    **extra: Any,
) -> Response:
    users = list(db.scalars(select(User).order_by(User.username)))
    context = page_context(
        user,
        sess,
        "users",
        users=users,
        roles=list(Role),
        role_labels=ROLE_LABELS,
        error=error,
        form_username=extra.pop("form_username", ""),
        form_role=extra.pop("form_role", Role.viewer.value),
        **extra,
    )
    return render(request, "users/list.html", context, status_code=status_code)


def _active_admins(db: DbSession) -> int:
    """Count active admins, row-locking them so concurrent demotions serialise (PostgreSQL)."""
    query = select(User.id).where(User.role == Role.admin, User.disabled.is_(False))
    return len(db.scalars(query.with_for_update()).all())


def _get_user(db: DbSession, user_id: uuid.UUID) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return target


def _removes_last_admin(db: DbSession, target: User) -> bool:
    return target.role is Role.admin and not target.disabled and _active_admins(db) <= 1


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    return _render_page(request, db, user, sess)


@router.post("")
async def create(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    form = await request.form()
    username = str(form.get("username") or "").strip()
    role_raw = str(form.get("role") or "")
    password = str(form.get("password") or "")

    def fail(message: str, code: int = 422) -> Response:
        return _render_page(
            request,
            db,
            user,
            sess,
            status_code=code,
            error=message,
            form_username=without_nul(username)[:64],
            form_role=role_raw,
        )

    if not USERNAME.fullmatch(username):
        return fail(USERNAME_MESSAGE)
    try:
        role = Role(role_raw)
    except ValueError:
        return fail(ROLE_MESSAGE)
    try:
        validate_password(password, username)
    except WeakPasswordError as exc:
        return fail(str(exc))
    if db.scalars(select(User.id).where(User.username == username)).first() is not None:
        return fail(DUPLICATE_MESSAGE, 409)
    new = User(
        id=uuid.uuid4(),
        username=username,
        password_hash=hash_password(password),
        totp_secret_enc=None,  # enrols TOTP on first login (existing flow)
        role=role,
        failed_logins=0,
        created_at=clock.now(),
    )
    db.add(new)
    try:
        db.flush()
    except IntegrityError:  # lost a race with a concurrent create of the same username
        db.rollback()
        return fail(DUPLICATE_MESSAGE, 409)
    audit.record(
        db,
        action="user.create",
        actor_user_id=user.id,
        actor_device_id=None,
        target=username,
        details={"role": role.value, "user_id": str(new.id), "via": "dashboard"},
    )
    db.commit()
    return _see_other("/users")


@router.post("/{user_id}/role")
async def change_role(
    user_id: uuid.UUID, request: Request, db: Db, user: CurrentUser, sess: CurrentSession
) -> Response:
    target = _get_user(db, user_id)
    try:
        role = Role(str((await request.form()).get("role") or ""))
    except ValueError:
        return _render_page(request, db, user, sess, status_code=422, error=ROLE_MESSAGE)
    if target.id == user.id:
        return _render_page(request, db, user, sess, status_code=409, error=SELF_MESSAGE)
    if role is not Role.admin and _removes_last_admin(db, target):
        return _render_page(request, db, user, sess, status_code=409, error=LAST_ADMIN_MESSAGE)
    if role is target.role:
        return _see_other("/users")
    before = target.role
    target.role = role
    audit.record(
        db,
        action="user.role_change",
        actor_user_id=user.id,
        actor_device_id=None,
        target=target.username,
        details={"user_id": str(target.id), "from": before.value, "to": role.value},
    )
    db.commit()
    return _see_other("/users")


@router.post("/{user_id}/disable")
def disable(
    user_id: uuid.UUID, request: Request, db: Db, user: CurrentUser, sess: CurrentSession
) -> Response:
    target = _get_user(db, user_id)
    if target.id == user.id:
        return _render_page(request, db, user, sess, status_code=409, error=SELF_MESSAGE)
    if _removes_last_admin(db, target):
        return _render_page(request, db, user, sess, status_code=409, error=LAST_ADMIN_MESSAGE)
    if not target.disabled:
        target.disabled = True
        audit.record(
            db,
            action="user.disable",
            actor_user_id=user.id,
            actor_device_id=None,
            target=target.username,
            details={"user_id": str(target.id)},
        )
        db.commit()
    return _see_other("/users")


@router.post("/{user_id}/enable")
def enable(user_id: uuid.UUID, db: Db, user: CurrentUser) -> Response:
    target = _get_user(db, user_id)
    if target.disabled:
        target.disabled = False
        audit.record(
            db,
            action="user.enable",
            actor_user_id=user.id,
            actor_device_id=None,
            target=target.username,
            details={"user_id": str(target.id)},
        )
        db.commit()
    return _see_other("/users")

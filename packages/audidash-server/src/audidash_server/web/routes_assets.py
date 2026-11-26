"""Asset registry pages: list, create, edit, delete (HTMX-enhanced, plain POST fallback)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession
from starlette.responses import RedirectResponse, Response

from audidash_server import audit, clock
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.rbac import require_role
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Asset, Role, Session, User
from audidash_server.services.assets import AssetCreate
from audidash_server.web import asset_queries, queries
from audidash_server.web.forms import Form
from audidash_server.web.layout import page_context

router = APIRouter(prefix="/assets")

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]
WRITE = [require_role(Role.admin, Role.analyst), Depends(csrf_protect)]
WRITE_GET = [require_role(Role.admin, Role.analyst)]

DUPLICATE_MESSAGE = "Já existe um ativo com esse nome"
REFERENCED_MESSAGE = "Não é possível excluir este ativo: há achados ou execuções associados a ele."
FIELD_MESSAGES = {
    "name": "Nome inválido: use de 1 a 128 caracteres, sem caracteres de controle.",
    "address": "Endereço inválido: use até 255 caracteres, sem caracteres de controle.",
    "asset_type": "Tipo inválido.",
    "criticality": "Criticidade inválida.",
    "tags": "Tags inválidas: no máximo 32 tags de até 64 caracteres, sem caracteres de controle.",
}
FIELDS = ("name", "address", "asset_type", "criticality", "tags")


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def _parse_tags(raw: str) -> list[str]:
    tags: list[str] = []
    for part in raw.split(","):
        tag = part.strip()
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def _form_values(form: Any) -> dict[str, str]:
    return {f: str(form.get(f) or "") for f in FIELDS}


def _validate(values: dict[str, str]) -> tuple[AssetCreate | None, dict[str, str]]:
    payload = {
        "name": values["name"].strip(),
        "address": values["address"].strip() or None,
        "asset_type": values["asset_type"],
        "criticality": values["criticality"],
        "tags": _parse_tags(values["tags"]),
    }
    try:
        return AssetCreate.model_validate(payload), {}
    except ValidationError as exc:
        errors: dict[str, str] = {}
        for err in exc.errors():
            field = str(err["loc"][0]) if err["loc"] else "name"
            errors[field] = FIELD_MESSAGES.get(field, "Valor inválido.")
        return None, errors


def _ctx(user: User, sess: Session, **extra: Any) -> dict[str, Any]:
    return page_context(
        user,
        sess,
        "assets",
        can_write=user.role in (Role.admin, Role.analyst),
        band_labels=queries.BAND_LABELS,
        criticality_labels=asset_queries.CRITICALITY_LABELS,
        asset_types=[t.value for t in TargetType],
        criticalities=list(Criticality),
        **extra,
    )


def _values_of(asset: Asset) -> dict[str, str]:
    return {
        "name": asset.name,
        "address": asset.address or "",
        "asset_type": asset.asset_type.value,
        "criticality": asset.criticality.value,
        "tags": ", ".join(asset.tags or []),
    }


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _render_list(
    request: Request,
    db: DbSession,
    user: User,
    sess: Session,
    *,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    context = _ctx(user, sess, rows=asset_queries.list_assets(db), error=error)
    return render(request, "assets/list.html", context, status_code=status_code)


def _render_form(
    request: Request,
    user: User,
    sess: Session,
    *,
    asset: Asset | None,
    values: dict[str, str],
    errors: dict[str, str],
    status_code: int = 200,
) -> Response:
    context = _ctx(user, sess, asset=asset, values=values, errors=errors)
    if _is_htmx(request):
        template = "assets/_edit_row.html" if asset is not None else "assets/_form.html"
    else:
        template = "assets/form.html"
    return render(request, template, context, status_code=status_code)


def _name_taken(db: DbSession, name: str, exclude: uuid.UUID | None = None) -> bool:
    query = select(Asset.id).where(Asset.name == name)
    if exclude is not None:
        query = query.where(Asset.id != exclude)
    return db.scalars(query).first() is not None


def _get_asset(db: DbSession, asset_id: uuid.UUID) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    return asset


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    return _render_list(request, db, user, sess)


@router.get("/new", dependencies=WRITE_GET)
def new_page(request: Request, user: CurrentUser, sess: CurrentSession) -> Response:
    empty = {f: "" for f in FIELDS}
    return _render_form(request, user, sess, asset=None, values=empty, errors={})


@router.post("", dependencies=WRITE)
def create(
    request: Request, db: Db, user: CurrentUser, sess: CurrentSession, form: Form
) -> Response:
    values = _form_values(form)
    data, errors = _validate(values)
    if data is not None and _name_taken(db, data.name):
        errors["name"] = DUPLICATE_MESSAGE
    if data is None or errors:
        return _render_form(
            request, user, sess, asset=None, values=values, errors=errors, status_code=422
        )
    asset = Asset(
        name=data.name,
        address=data.address,
        asset_type=data.asset_type,
        criticality=data.criticality,
        tags=list(data.tags),
        created_at=clock.now(),
    )
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:  # lost a race with a concurrent create of the same name
        db.rollback()
        return _render_form(
            request,
            user,
            sess,
            asset=None,
            values=values,
            errors={"name": DUPLICATE_MESSAGE},
            status_code=422,
        )
    audit.record(
        db,
        action="asset.create",
        actor_user_id=user.id,
        actor_device_id=None,
        target=asset.name,
        details={
            "asset_id": str(asset.id),
            "asset_type": str(asset.asset_type),
            "criticality": str(asset.criticality),
        },
    )
    db.commit()
    if _is_htmx(request):
        return Response(status_code=200, headers={"HX-Redirect": "/assets"})
    return _see_other("/assets")


@router.get("/{asset_id}/edit", dependencies=WRITE_GET)
def edit_page(
    asset_id: uuid.UUID, request: Request, db: Db, user: CurrentUser, sess: CurrentSession
) -> Response:
    asset = _get_asset(db, asset_id)
    return _render_form(request, user, sess, asset=asset, values=_values_of(asset), errors={})


@router.post("/{asset_id}", dependencies=WRITE)
def update(
    asset_id: uuid.UUID,
    request: Request,
    db: Db,
    user: CurrentUser,
    sess: CurrentSession,
    form: Form,
) -> Response:
    asset = _get_asset(db, asset_id)
    values = _form_values(form)
    data, errors = _validate(values)
    if data is not None and _name_taken(db, data.name, exclude=asset.id):
        errors["name"] = DUPLICATE_MESSAGE
    if data is None or errors:
        return _render_form(
            request, user, sess, asset=asset, values=values, errors=errors, status_code=422
        )
    new = {
        "name": data.name,
        "address": data.address,
        "asset_type": data.asset_type,
        "criticality": data.criticality,
        "tags": list(data.tags),
    }
    changed = sorted(f for f, v in new.items() if getattr(asset, f) != v)
    for field, value in new.items():
        setattr(asset, field, value)
    try:
        db.flush()
    except IntegrityError:  # lost a race with a concurrent rename to the same name
        db.rollback()
        return _render_form(
            request,
            user,
            sess,
            asset=db.get(Asset, asset_id),
            values=values,
            errors={"name": DUPLICATE_MESSAGE},
            status_code=422,
        )
    audit.record(
        db,
        action="asset.update",
        actor_user_id=user.id,
        actor_device_id=None,
        target=asset.name,
        details={"asset_id": str(asset.id), "changed": changed},
    )
    db.commit()
    if not _is_htmx(request):
        return _see_other("/assets")
    rows = asset_queries.list_assets(db, only=asset.id)
    return render(request, "assets/_row.html", _ctx(user, sess, row=rows[0], row_error=None))


@router.post("/{asset_id}/delete", dependencies=WRITE)
def delete(
    asset_id: uuid.UUID, request: Request, db: Db, user: CurrentUser, sess: CurrentSession
) -> Response:
    asset = _get_asset(db, asset_id)
    refused = asset_queries.is_referenced(db, asset.id)
    if not refused:
        name, aid = asset.name, str(asset.id)
        db.delete(asset)
        try:
            db.flush()
        except IntegrityError:  # a finding or run appeared concurrently (FK is RESTRICT)
            db.rollback()
            refused = True
    if refused:
        if _is_htmx(request):
            row = asset_queries.list_assets(db, only=asset_id)[0]
            context = _ctx(user, sess, row=row, row_error=REFERENCED_MESSAGE)
            return render(request, "assets/_row.html", context, status_code=409)
        return _render_list(request, db, user, sess, error=REFERENCED_MESSAGE, status_code=409)
    audit.record(
        db,
        action="asset.delete",
        actor_user_id=user.id,
        actor_device_id=None,
        target=name,
        details={"asset_id": aid},
    )
    db.commit()
    if _is_htmx(request):
        return Response(status_code=200)  # empty body: outerHTML swap removes the row
    return _see_other("/assets")

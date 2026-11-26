"""Findings pages: filtered list, detail with history, and lifecycle actions."""

from __future__ import annotations

import unicodedata
import uuid
from typing import Annotated, Any

from audidash_core.findings import FindingStatus, Severity
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession
from starlette.responses import RedirectResponse, Response

from audidash_server import audit
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.rbac import require_role
from audidash_server.auth.routes import render
from audidash_server.auth.sessions import current_session, current_user
from audidash_server.db import get_session
from audidash_server.models import Asset, FindingRecord, Role, Session, User
from audidash_server.services import lifecycle
from audidash_server.web import finding_queries as fq
from audidash_server.web.layout import page_context

router = APIRouter(prefix="/findings")

Db = Annotated[DbSession, Depends(get_session)]
CurrentUser = Annotated[User, Depends(current_user)]
CurrentSession = Annotated[Session, Depends(current_session)]
WRITE = [require_role(Role.admin, Role.analyst), Depends(csrf_protect)]

MAX_JUSTIFICATION = 1000
ILLEGAL_MESSAGE = "Transição de status não permitida para o estado atual deste achado."
CHANGED_MESSAGE = "O achado foi alterado por outra ação. Atualize a página e tente novamente."
JUSTIFICATION_MESSAGE = (
    "Justificativa obrigatória: informe de 1 a 1000 caracteres, sem caracteres de controle."
)
ACTION_LABELS: dict[FindingStatus, str] = {
    FindingStatus.acknowledged: "Reconhecer",
    FindingStatus.resolved: "Marcar como resolvido",
    FindingStatus.false_positive: "Falso positivo",
    FindingStatus.accepted_risk: "Aceitar risco",
    FindingStatus.open: "Reabrir",
}
ACTION_ORDER = (
    FindingStatus.acknowledged,
    FindingStatus.resolved,
    FindingStatus.false_positive,
    FindingStatus.accepted_risk,
    FindingStatus.open,
)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def _is_history_restore(request: Request) -> bool:
    return request.headers.get("HX-History-Restore-Request") == "true"


def _clean_justification(raw: str) -> str | None:
    """Trimmed text of 1..1000 chars; newlines/tabs allowed, other control chars rejected."""
    text = raw.replace("\r\n", "\n").strip()
    if not 0 < len(text) <= MAX_JUSTIFICATION:
        return None
    for ch in text:
        if ch not in "\n\t" and unicodedata.category(ch) in ("Cc", "Cs"):
            return None
    return text


def _actions_for(status: FindingStatus) -> list[tuple[FindingStatus, str]]:
    return [
        (target, ACTION_LABELS[target])
        for target in ACTION_ORDER
        if status in lifecycle.MANUAL_TRANSITIONS[target]
    ]


def _ctx(user: User, sess: Session, **extra: Any) -> dict[str, Any]:
    return page_context(
        user,
        sess,
        "findings",
        can_write=user.role in (Role.admin, Role.analyst),
        status_labels=fq.STATUS_LABELS,
        severity_labels=fq.SEVERITY_LABELS,
        category_labels=fq.CATEGORY_LABELS,
        **extra,
    )


def _detail_context(
    db: DbSession, rec: FindingRecord, user: User, sess: Session, **extra: Any
) -> dict[str, Any]:
    asset = db.get(Asset, rec.asset_id)
    return _ctx(
        user,
        sess,
        finding=rec,
        asset=asset,
        references=fq.reference_links(list(rec.references or [])),
        history=fq.history(db, rec.id),
        actions=_actions_for(rec.status),
        error=extra.pop("error", None),
        justification_value=extra.pop("justification_value", ""),
        **extra,
    )


@router.get("")
def list_page(request: Request, db: Db, user: CurrentUser, sess: CurrentSession) -> Response:
    filters = fq.parse_filters(request.query_params)
    page = fq.list_findings(db, filters)
    assets, plugins = fq.filter_options(db)
    context = _ctx(
        user,
        sess,
        page=page,
        filters=filters,
        filter_assets=assets,
        filter_plugins=plugins,
        severities=list(reversed(list(Severity))),
        categories=list(fq.CATEGORY_LABELS),
        statuses=list(FindingStatus),
        status_all=fq.STATUS_ALL,
    )
    fragment = _is_htmx(request) and not _is_history_restore(request)
    response = render(
        request, "findings/_results.html" if fragment else "findings/list.html", context
    )
    response.headers["Vary"] = "HX-Request, HX-History-Restore-Request"
    return response


def _get_finding(db: DbSession, finding_id: uuid.UUID) -> FindingRecord:
    rec = db.get(FindingRecord, finding_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Achado não encontrado")
    return rec


@router.get("/{finding_id}")
def detail_page(
    finding_id: uuid.UUID, request: Request, db: Db, user: CurrentUser, sess: CurrentSession
) -> Response:
    rec = _get_finding(db, finding_id)
    return render(request, "findings/detail.html", _detail_context(db, rec, user, sess))


def _error_response(
    request: Request,
    db: DbSession,
    rec: FindingRecord,
    user: User,
    sess: Session,
    *,
    status_code: int,
    message: str,
    justification: str,
) -> Response:
    context = _detail_context(db, rec, user, sess, error=message, justification_value=justification)
    template = "findings/_lifecycle.html" if _is_htmx(request) else "findings/detail.html"
    return render(request, template, context, status_code=status_code)


@router.post("/{finding_id}/status", dependencies=WRITE)
async def change_status(
    finding_id: uuid.UUID, request: Request, db: Db, user: CurrentUser, sess: CurrentSession
) -> Response:
    rec = _get_finding(db, finding_id)
    form = await request.form()
    raw_to = str(form.get("to") or "")
    raw_justification = str(form.get("justification") or "")

    def fail(code: int, message: str) -> Response:
        return _error_response(
            request,
            db,
            rec,
            user,
            sess,
            status_code=code,
            message=message,
            justification=raw_justification,
        )

    try:
        target = FindingStatus(raw_to)
    except ValueError:
        return fail(409, ILLEGAL_MESSAGE)
    allowed_from = lifecycle.MANUAL_TRANSITIONS.get(target)
    if allowed_from is None or rec.status not in allowed_from:
        return fail(409, ILLEGAL_MESSAGE)

    justification: str | None = None
    if target in lifecycle.JUSTIFICATION_REQUIRED or raw_justification.strip():
        justification = _clean_justification(raw_justification)
        if justification is None:
            return fail(422, JUSTIFICATION_MESSAGE)
    if target is FindingStatus.open:
        justification = None  # reopening clears the earlier decision's justification

    moved_from = lifecycle.try_transition(
        db,
        rec.id,
        to_status=target,
        allowed_from=allowed_from,
        user_id=user.id,
        run_id=None,
        justification=justification,
    )
    if moved_from is None:  # lost a race with another writer (analyst or ingest)
        db.rollback()
        fresh = _get_finding(db, finding_id)
        return _error_response(
            request,
            db,
            fresh,
            user,
            sess,
            status_code=409,
            message=CHANGED_MESSAGE,
            justification=raw_justification,
        )
    audit.record(
        db,
        action="finding.status_change",
        actor_user_id=user.id,
        actor_device_id=None,
        target=str(rec.id),
        details={
            "from": moved_from.value,
            "to": target.value,
            "finding_id": str(rec.id),
            "has_justification": justification is not None,
        },
    )
    db.commit()
    if _is_htmx(request):
        db.refresh(rec)
        context = _detail_context(db, rec, user, sess)
        return render(request, "findings/_lifecycle.html", context)
    return RedirectResponse(f"/findings/{rec.id}", status_code=303)

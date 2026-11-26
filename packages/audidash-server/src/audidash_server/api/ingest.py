"""POST /api/v1/runs (mTLS + bearer, analyst/admin): upload one run result."""

from __future__ import annotations

import uuid

from audidash_core.runner import RunResult
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from audidash_server.api.deps import Db, Writer
from audidash_server.api.errors import sanitized_errors
from audidash_server.services.ingest import IngestError, ingest_run
from audidash_server.textguard import nul_path

router = APIRouter(prefix="/api/v1")

MAX_BODY_BYTES = 5 * 1024 * 1024


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: uuid.UUID
    asset: str = Field(min_length=1, max_length=128)
    result: RunResult


async def read_limited_body(request: Request, limit: int = MAX_BODY_BYTES) -> bytes:
    """Request body, refusing (413) anything over `limit` bytes before or while reading it."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if size > limit:
            raise HTTPException(status_code=413, detail="request body too large")
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/runs", status_code=201)
async def upload_run(
    request: Request,
    db: Db,
    principal: Writer,
) -> JSONResponse:
    raw = await read_limited_body(request)
    try:
        body = IngestRequest.model_validate_json(raw)
    except ValidationError as exc:
        return JSONResponse({"detail": sanitized_errors(exc.errors())}, status_code=422)
    nul_field = nul_path(body.model_dump())
    if nul_field is not None:  # PostgreSQL text cannot hold NUL: reject before any query
        detail = f"{nul_field} must not contain NUL (0x00) characters"
        return JSONResponse({"detail": detail}, status_code=422)
    try:
        outcome = await run_in_threadpool(
            ingest_run,
            db,
            run_id=body.run_id,
            asset_name=body.asset,
            result=body.result,
            device=principal.device,
            user=principal.user,
        )
    except IngestError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
    return JSONResponse(outcome.summary, status_code=201 if outcome.created else 200)

"""JSON error rendering for request validation that never echoes submitted values."""

from __future__ import annotations

from typing import Any

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.responses import Response


def sanitized_errors(errors: Any) -> list[dict[str, Any]]:
    """Keep only location, message and type: `input`/`ctx` may contain passwords."""
    return [
        {"loc": list(err.get("loc", ())), "msg": str(err.get("msg", "")), "type": err.get("type")}
        for err in errors
    ]


async def validation_error_handler(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, RequestValidationError):  # registered for this type only
        raise exc
    return JSONResponse({"detail": sanitized_errors(exc.errors())}, status_code=422)

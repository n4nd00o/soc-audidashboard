"""Form body as a dependency, so state-changing routes can be plain (threadpool) functions.

Parsing the body needs `await`; doing it in this small async dependency lets the route itself
be a sync `def`, which FastAPI runs in the threadpool - blocking SQLAlchemy and Argon2 work
never stalls the event loop. Starlette caches the parsed form on the request, so the CSRF
check and the route share one parse.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from starlette.datastructures import FormData


async def read_form(request: Request) -> FormData:
    return await request.form()


Form = Annotated[FormData, Depends(read_form)]


def form_text(form: FormData, field: str) -> str:
    """The field as text ('' when missing or an uploaded file)."""
    value = form.get(field)
    return value if isinstance(value, str) else ""

"""Role-based access control on top of `current_user`."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, HTTPException

from audidash_server.auth.sessions import current_user
from audidash_server.models import Role, User


def require_role(*roles: Role) -> Any:
    """Dependency marker: the current user must hold one of `roles`, else 403.

    Usage: `user: User = require_role(Role.admin)` or `dependencies=[require_role(...)]`.
    """
    if not roles:
        raise ValueError("require_role needs at least one role")
    allowed = frozenset(roles)

    def _check(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return Depends(_check)

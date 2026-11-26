"""Shared page context for authenticated dashboard pages (navigation, CSRF, current user)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from audidash_server.models import Role, Session, User


@dataclass(frozen=True)
class NavItem:
    key: str
    label: str
    href: str
    admin_only: bool = False


NAV_ITEMS: tuple[NavItem, ...] = (
    NavItem("overview", "Visão geral", "/"),
    NavItem("assets", "Ativos", "/assets"),
    NavItem("findings", "Achados", "/findings"),
    NavItem("runs", "Execuções", "/runs"),
    NavItem("plugins", "Plugins", "/plugins"),
    NavItem("devices", "Dispositivos", "/devices"),
    NavItem("users", "Usuários", "/users", admin_only=True),
    NavItem("audit", "Auditoria", "/audit", admin_only=True),
)


def nav_for(user: User) -> list[NavItem]:
    return [i for i in NAV_ITEMS if not i.admin_only or user.role is Role.admin]


def page_context(user: User, sess: Session, current: str, **extra: Any) -> dict[str, Any]:
    return {
        "user": user,
        "csrf_token": sess.csrf_token,
        "nav_items": nav_for(user),
        "current_nav": current,
        **extra,
    }

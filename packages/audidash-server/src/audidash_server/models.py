"""SQLAlchemy 2.0 data model (portable across SQLite and PostgreSQL)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from audidash_core.catalog import Trust
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus
from audidash_core.scoring import Criticality
from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    Uuid,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class StrEnumType[E: StrEnum](TypeDecorator[E]):
    """Store a StrEnum as a plain string, validating the value on write and read."""

    impl = String(32)
    cache_ok = True

    def __init__(self, enum_cls: type[E]) -> None:
        super().__init__()
        self.enum_cls = enum_cls

    def process_bind_param(self, value: E | str | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return str(self.enum_cls(value).value)

    def process_result_value(self, value: str | None, dialect: Dialect) -> E | None:
        if value is None:
            return None
        return self.enum_cls(value)


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware datetime; SQLite drops tzinfo, so re-attach UTC on read."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime not allowed")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {  # noqa: RUF012
        datetime: UTCDateTime,
    }


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, default=None)
    # Last accepted TOTP time step: a code is single-use within its validity window.
    totp_last_step: Mapped[int | None] = mapped_column(Integer, default=None)
    role: Mapped[Role] = mapped_column(StrEnumType(Role))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    disabled: Mapped[bool] = mapped_column(default=False)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_user_id", "user_id"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # Only sha256(cookie token) is stored; the cookie value itself never touches the DB.
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # True while a first-login user must still enrol TOTP (not a full session).
    mfa_pending: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    csrf_token: Mapped[str] = mapped_column(String(128))
    ip: Mapped[str | None] = mapped_column(String(64), default=None)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128))
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    cert_fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True, default=None)
    cert_not_after: Mapped[datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime]


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None] = mapped_column(default=None)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), default=None
    )


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime]


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True)
    address: Mapped[str | None] = mapped_column(String(255), default=None)
    asset_type: Mapped[TargetType] = mapped_column(StrEnumType(TargetType))
    criticality: Mapped[Criticality] = mapped_column(StrEnumType(Criticality))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime]


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (Index("ix_runs_asset_id_finished_at", "asset_id", "finished_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)  # client-supplied run_id
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), index=True, default=None
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True, default=None
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"))
    plugin_id: Mapped[str] = mapped_column(String(128))
    plugin_version: Mapped[str] = mapped_column(String(64))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    trust: Mapped[Trust | None] = mapped_column(StrEnumType(Trust), default=None)
    status: Mapped[RunStatus] = mapped_column(StrEnumType(RunStatus))
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime]
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    received_at: Mapped[datetime]


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_asset_id_status", "asset_id", "status"),
        Index("ix_findings_asset_id_plugin_id", "asset_id", "plugin_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"))
    plugin_id: Mapped[str] = mapped_column(String(128))
    finding_id: Mapped[str] = mapped_column(String(128))
    item_key: Mapped[str] = mapped_column(String(512), default="")
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity))
    category: Mapped[Category] = mapped_column(StrEnumType(Category))
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[FindingStatus] = mapped_column(StrEnumType(FindingStatus))
    justification: Mapped[str | None] = mapped_column(Text, default=None)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL"), index=True, default=None
    )
    status_changed_at: Mapped[datetime | None] = mapped_column(default=None)
    status_changed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )


class FindingEvent(Base):
    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_events_finding_id", "finding_id"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runs.id", ondelete="SET NULL"), default=None
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    from_status: Mapped[FindingStatus | None] = mapped_column(
        StrEnumType(FindingStatus), default=None
    )
    to_status: Mapped[FindingStatus] = mapped_column(StrEnumType(FindingStatus))
    justification: Mapped[str | None] = mapped_column(Text, default=None)
    at: Mapped[datetime]


class VerifiedPlugin(Base):
    __tablename__ = "verified_plugins"

    id: Mapped[uuid.UUID] = _uuid_pk()
    manifest_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    plugin_id: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    approved_at: Mapped[datetime]


class AuditEntry(Base):
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    at: Mapped[datetime]
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, default=None)
    actor_device_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, default=None)
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(255), default=None)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))

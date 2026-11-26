import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from audidash_core.catalog import Trust
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus
from audidash_core.scoring import Criticality
from audidash_server.app import create_app
from audidash_server.db import get_session, make_engine, run_migrations
from audidash_server.models import Asset, Base, FindingRecord, Role, Run, Session, User
from audidash_server.settings import Settings
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session as DbSession


def _now() -> datetime:
    return datetime.now(UTC)


def _asset(name: str = "srv-1") -> Asset:
    return Asset(
        id=uuid.uuid4(),
        name=name,
        address="10.0.0.1",
        asset_type=TargetType.linux,
        criticality=Criticality.high,
        tags=["prod"],
        created_at=_now(),
    )


def _finding(asset_id: uuid.UUID, fingerprint: str = "fp1") -> FindingRecord:
    return FindingRecord(
        id=uuid.uuid4(),
        fingerprint=fingerprint,
        asset_id=asset_id,
        plugin_id="p",
        finding_id="f",
        item_key="k",
        title="t",
        severity=Severity.high,
        category=Category.misconfiguration,
        evidence="e",
        recommendation="r",
        references=["https://example.org"],
        status=FindingStatus.open,
        first_seen=_now(),
        last_seen=_now(),
    )


def test_asset_name_unique(db_session: DbSession) -> None:
    db_session.add(_asset("dup"))
    db_session.commit()
    db_session.add(_asset("dup"))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_fingerprint_unique(db_session: DbSession) -> None:
    asset = _asset()
    db_session.add(asset)
    db_session.commit()
    db_session.add(_finding(asset.id, "same"))
    db_session.commit()
    db_session.add(_finding(asset.id, "same"))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_enum_roundtrip_and_validation(db_session: DbSession) -> None:
    asset = _asset()
    db_session.add(asset)
    db_session.commit()
    db_session.expire_all()
    loaded = db_session.get(Asset, asset.id)
    assert loaded is not None
    assert loaded.asset_type is TargetType.linux
    assert loaded.criticality is Criticality.high
    assert loaded.tags == ["prod"]
    assert loaded.created_at.tzinfo is not None

    bad = _asset("bad")
    bad.asset_type = "not-a-type"  # type: ignore[assignment]
    db_session.add(bad)
    with pytest.raises(StatementError):
        db_session.commit()


def test_asset_delete_restricted_by_findings(db_session: DbSession) -> None:
    asset = _asset()
    db_session.add(asset)
    db_session.commit()
    db_session.add(_finding(asset.id))
    db_session.commit()
    db_session.delete(asset)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_user_delete_cascades_sessions(db_session: DbSession) -> None:
    user = User(
        id=uuid.uuid4(),
        username="alice",
        password_hash="x",  # noqa: S106
        role=Role.analyst,
        failed_logins=0,
        created_at=_now(),
        disabled=False,
    )
    db_session.add(user)
    db_session.commit()
    sid_id = uuid.uuid4()
    sess = Session(
        id=sid_id,
        user_id=user.id,
        token_sha256="0" * 64,
        created_at=_now(),
        last_seen_at=_now(),
        csrf_token="c",  # noqa: S106
        ip="127.0.0.1",
    )
    db_session.add(sess)
    db_session.commit()
    db_session.delete(user)
    db_session.commit()
    assert db_session.get(Session, sid_id) is None


def test_migration_matches_models(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    run_migrations(url)
    engine = make_engine(url)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(ctx, Base.metadata) == []
        tables = set(inspect(conn).get_table_names())
    assert set(Base.metadata.tables) <= tables
    engine.dispose()


def test_naive_datetime_rejected_on_bind(db_session: DbSession) -> None:
    asset = _asset("naive")
    asset.created_at = datetime(2026, 1, 1)  # noqa: DTZ001
    db_session.add(asset)
    with pytest.raises(StatementError):
        db_session.commit()


def test_aware_datetime_roundtrip_and_comparison(db_session: DbSession) -> None:
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    asset = _asset("aware")
    asset.created_at = stamp
    db_session.add(asset)
    db_session.commit()
    db_session.expire_all()
    loaded = db_session.get(Asset, asset.id)
    assert loaded is not None
    assert loaded.created_at == stamp
    assert loaded.created_at < datetime.now(UTC)
    found = db_session.scalars(select(Asset).where(Asset.created_at < datetime.now(UTC))).all()
    assert [a.name for a in found] == ["aware"]


def test_run_trust_and_status_are_validated_enums(db_session: DbSession) -> None:
    asset = _asset()
    db_session.add(asset)
    db_session.commit()
    run = Run(
        id=uuid.uuid4(),
        asset_id=asset.id,
        plugin_id="p",
        plugin_version="1",
        manifest_sha256="a" * 64,
        trust=Trust.official,
        status="bogus",
        started_at=_now(),
        finished_at=_now(),
        received_at=_now(),
    )
    db_session.add(run)
    with pytest.raises(StatementError):
        db_session.commit()
    db_session.rollback()
    assert max(len(m.value) for m in (*Trust, *RunStatus)) <= 32


def test_get_session_never_auto_commits(settings: Settings) -> None:
    app = create_app(settings)

    @app.post("/_t/forgot")
    def forgot(db: DbSession = Depends(get_session)) -> dict[str, str]:  # noqa: B008
        db.add(_asset("uncommitted"))
        db.flush()
        return {"ok": "1"}

    @app.post("/_t/dup")
    def dup(db: DbSession = Depends(get_session)) -> dict[str, str]:  # noqa: B008
        db.add(_asset("dup-a"))
        db.add(_asset("dup-a"))
        db.commit()
        return {"ok": "1"}

    client = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
    assert client.post("/_t/dup").status_code == 500
    assert client.post("/_t/forgot").status_code == 200
    with app.state.sessionmaker() as s:
        assert s.scalars(select(Asset)).all() == []

from typing import Any

import pytest
from audidash_server import audit, cli
from audidash_server.audit import GENESIS_HASH, record, verify_chain
from audidash_server.models import AuditEntry
from audidash_server.settings import Settings
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as DbSession


def _add(db: DbSession, n: int) -> None:
    for i in range(n):
        record(
            db,
            action="asset.create",
            actor_user_id=None,
            actor_device_id=None,
            target=f"asset:{i}",
            details={"name": f"ação {i}"},
        )
    db.commit()


def test_empty_chain_is_valid(db_session: DbSession) -> None:
    assert verify_chain(db_session) is None


def test_chain_of_three_verifies_and_links(db_session: DbSession) -> None:
    _add(db_session, 3)
    rows = db_session.scalars(select(AuditEntry).order_by(AuditEntry.seq)).all()
    assert rows[0].prev_hash == GENESIS_HASH
    assert rows[1].prev_hash == rows[0].row_hash
    assert rows[2].prev_hash == rows[1].row_hash
    assert verify_chain(db_session) is None


def test_record_does_not_commit(db_session: DbSession) -> None:
    record(
        db_session,
        action="user.create",
        actor_user_id=None,
        actor_device_id=None,
        target="x",
        details={},
    )
    db_session.rollback()
    assert db_session.scalars(select(AuditEntry)).first() is None


def test_modified_row_detected(db_session: DbSession) -> None:
    _add(db_session, 3)
    db_session.execute(
        update(AuditEntry).where(AuditEntry.seq == 2).values(details={"name": "forjado"})
    )
    db_session.commit()
    db_session.expire_all()
    assert verify_chain(db_session) == 2


def test_deleted_row_detected(db_session: DbSession) -> None:
    _add(db_session, 3)
    db_session.execute(delete(AuditEntry).where(AuditEntry.seq == 2))
    db_session.commit()
    db_session.expire_all()
    assert verify_chain(db_session) == 3


def test_reordered_rows_detected(db_session: DbSession) -> None:
    _add(db_session, 3)
    db_session.execute(update(AuditEntry).where(AuditEntry.seq == 2).values(seq=99))
    db_session.execute(update(AuditEntry).where(AuditEntry.seq == 3).values(seq=2))
    db_session.commit()
    db_session.expire_all()
    assert verify_chain(db_session) == 2


@pytest.mark.parametrize(
    "key", ["password", "Secret_key", "api_token", "totp", "otp_code", "Evidence", "x_PASSWORD_y"]
)
def test_secretish_detail_keys_rejected(db_session: DbSession, key: str) -> None:
    with pytest.raises(ValueError, match="secret"):
        record(
            db_session,
            action="asset.update",
            actor_user_id=None,
            actor_device_id=None,
            target="t",
            details={"ok": 1, "nested": {key: "v"}},
        )


def test_login_failure_audited_without_password(
    app_client: TestClient, make_user: Any, login: Any
) -> None:
    u = make_user()
    login(u.username, "Wrong-password-123", "000000")
    login("ghost", "Another-wrong-pass-9", "000000")
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        rows = s.scalars(select(AuditEntry).order_by(AuditEntry.seq)).all()
        failures = [r for r in rows if r.action == "login.failure"]
        assert [r.details for r in failures] == [
            {"username": u.username, "reason": "invalid"},
            {"username": "ghost", "reason": "invalid"},
        ]
        blob = repr([(r.details, r.target) for r in rows])
        assert "Wrong-password-123" not in blob
        assert "Another-wrong-pass-9" not in blob
        assert verify_chain(s) is None


def test_login_success_audited(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 303
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        rows = s.scalars(select(AuditEntry).where(AuditEntry.action == "login.success")).all()
        assert len(rows) == 1
        assert rows[0].actor_user_id == u.id
        assert verify_chain(s) is None


def test_cli_audit_verify_ok_and_broken(
    settings: Settings, db_session: DbSession, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setenv("AUDIDASH_DATABASE_URL", settings.database_url)
    _add(db_session, 3)
    assert cli.main(["audit", "verify"]) == 0
    assert "audit chain OK (3 entries)" in capsys.readouterr().out

    db_session.execute(
        update(AuditEntry).where(AuditEntry.seq == 2).values(details={"name": "forjado"})
    )
    db_session.commit()
    assert cli.main(["audit", "verify"]) == 1
    assert "audit chain BROKEN at seq 2" in capsys.readouterr().out


def test_canonical_json_is_stable() -> None:
    from datetime import UTC, datetime

    c = audit._canonical(
        at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        actor_user_id=None,
        actor_device_id=None,
        action="a",
        target="t",
        details={"b": 1, "a": "é"},
    )
    assert c == (
        '{"action":"a","actor_device_id":null,"actor_user_id":null,'
        '"at":"2026-01-02T03:04:05.000000+00:00","details":{"a":"é","b":1},"target":"t"}'
    )

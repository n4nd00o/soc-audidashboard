import multiprocessing
import os
import stat
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from audidash_core.catalog import Trust
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus
from audidash_core.scoring import Criticality
from audidash_server import cli
from audidash_server.audit import verify_chain
from audidash_server.ca import CAError, load_existing_ca, load_or_create_ca
from audidash_server.models import (
    Asset,
    AuditEntry,
    EnrollmentToken,
    FindingEvent,
    FindingRecord,
    Role,
    Run,
    User,
)
from audidash_server.settings import Settings
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

PASSPHRASE = "p" * 32
NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def ops_env(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("AUDIDASH_DEV_MODE", "1")
    monkeypatch.setenv("AUDIDASH_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("AUDIDASH_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("AUDIDASH_SECRET_KEY", "s" * 32)
    monkeypatch.setenv("AUDIDASH_CA_PASSPHRASE", PASSPHRASE)
    return settings


def _asset(db: DbSession) -> Asset:
    asset = Asset(
        id=uuid.uuid4(),
        name="srv",
        address=None,
        asset_type=TargetType.linux,
        criticality=Criticality.high,
        tags=[],
        created_at=NOW,
    )
    db.add(asset)
    db.flush()
    return asset


def _run(asset: Asset, finished: datetime) -> Run:
    return Run(
        id=uuid.uuid4(),
        asset_id=asset.id,
        plugin_id="p",
        plugin_version="1",
        manifest_sha256="a" * 64,
        trust=Trust.official,
        status=RunStatus.ok,
        started_at=finished,
        finished_at=finished,
        received_at=finished,
    )


def _finding(asset: Asset, fp: str, last_seen: datetime, run: Run | None) -> FindingRecord:
    return FindingRecord(
        id=uuid.uuid4(),
        fingerprint=fp,
        asset_id=asset.id,
        plugin_id="p",
        finding_id="f",
        item_key=fp,
        title="t",
        severity=Severity.high,
        category=Category.misconfiguration,
        status=FindingStatus.open,
        first_seen=last_seen,
        last_seen=last_seen,
        last_run_id=run.id if run else None,
    )


def _seed(db: DbSession) -> dict[str, Any]:
    """Old run + old finding, recent run + finding; the recent finding points at the old run."""
    asset = _asset(db)
    old_run = _run(asset, NOW - timedelta(days=400))
    new_run = _run(asset, NOW - timedelta(days=10))
    db.add_all([old_run, new_run])
    db.flush()
    old_f = _finding(asset, "old", NOW - timedelta(days=400), old_run)
    kept_f = _finding(asset, "kept", NOW - timedelta(days=5), old_run)  # refs a purged run
    db.add_all([old_f, kept_f])
    db.flush()
    for finding in (old_f, kept_f):
        db.add(
            FindingEvent(
                id=uuid.uuid4(),
                finding_id=finding.id,
                run_id=old_run.id,
                from_status=None,
                to_status=FindingStatus.open,
                at=NOW - timedelta(days=5),
            )
        )
    db.commit()
    return {"old_run": old_run.id, "new_run": new_run.id, "old_f": old_f.id, "kept_f": kept_f.id}


def _count(db: DbSession, model: Any) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0


def test_purge_dry_run_changes_nothing(
    ops_env: Settings, db_session: DbSession, frozen_clock: Any, capsys: Any
) -> None:
    frozen_clock.current = NOW
    _seed(db_session)
    assert cli.main(["purge", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "[dry-run]" in out
    assert "1 execuções, 1 achados, 1 eventos" in out
    db_session.expire_all()
    assert _count(db_session, Run) == 2
    assert _count(db_session, FindingRecord) == 2
    assert _count(db_session, FindingEvent) == 2
    assert _count(db_session, AuditEntry) == 0


def test_purge_deletes_old_rows_nulls_references_and_audits(
    ops_env: Settings, db_session: DbSession, frozen_clock: Any, capsys: Any
) -> None:
    frozen_clock.current = NOW
    ids = _seed(db_session)
    assert cli.main(["purge"]) == 0
    assert "removidos: 1 execuções, 1 achados, 1 eventos" in capsys.readouterr().out
    db_session.expire_all()
    assert db_session.get(Run, ids["old_run"]) is None
    assert db_session.get(Run, ids["new_run"]) is not None
    assert db_session.get(FindingRecord, ids["old_f"]) is None
    kept = db_session.get(FindingRecord, ids["kept_f"])
    assert kept is not None
    assert kept.last_run_id is None  # SET NULL, no integrity error
    assert _count(db_session, FindingEvent) == 1
    event = db_session.scalars(select(FindingEvent)).one()
    assert event.run_id is None
    entry = db_session.scalars(
        select(AuditEntry).where(AuditEntry.action == "retention.purge")
    ).one()
    assert entry.details["runs"] == 1
    assert entry.details["findings"] == 1
    assert entry.details["events"] == 1
    assert entry.details["retention_days"] == 365
    assert entry.details["cutoff"] == (NOW - timedelta(days=365)).isoformat()
    assert verify_chain(db_session) is None


def test_purge_respects_retention_days(
    ops_env: Settings, db_session: DbSession, frozen_clock: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen_clock.current = NOW
    _seed(db_session)
    monkeypatch.setenv("AUDIDASH_RETENTION_DAYS", "3650")
    assert cli.main(["purge"]) == 0
    db_session.expire_all()
    assert _count(db_session, Run) == 2


def test_purge_reports_db_errors_cleanly(
    ops_env: Settings, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    # No tables were created: the query fails.
    assert cli.main(["purge"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("erro: banco de dados inacessível")
    assert len(err.strip().splitlines()) == 1


def test_ops_commands_require_production_config(
    monkeypatch: pytest.MonkeyPatch, capsys: Any, tmp_path: Path
) -> None:
    monkeypatch.delenv("AUDIDASH_DEV_MODE", raising=False)
    monkeypatch.delenv("AUDIDASH_SECRET_KEY", raising=False)
    monkeypatch.delenv("AUDIDASH_PROXY_SECRET", raising=False)
    monkeypatch.delenv("AUDIDASH_CA_PASSPHRASE", raising=False)
    monkeypatch.setenv("AUDIDASH_DATABASE_URL", f"sqlite:///{tmp_path.as_posix()}/x.db")
    for argv in (["purge"], ["init-ca"], ["show-ca-fingerprint"], ["create-enrollment-token"]):
        assert cli.main(argv) == 2
        err = capsys.readouterr().err
        assert "Invalid production configuration" in err
        assert len(err.strip().splitlines()) == 1


def test_show_ca_fingerprint_requires_init_then_matches(ops_env: Settings, capsys: Any) -> None:
    assert cli.main(["show-ca-fingerprint"]) == 1
    assert "CA not initialised — run init-ca" in capsys.readouterr().err
    assert not (ops_env.data_dir / "ca").exists()  # never created as a side effect

    assert cli.main(["init-ca"]) == 0
    out = capsys.readouterr().out
    assert "CA criada." in out
    ca = load_existing_ca(ops_env.data_dir, SecretStr(PASSPHRASE))
    assert ca is not None
    assert ca.fingerprint_sha256() in out

    assert cli.main(["init-ca"]) == 0  # idempotent
    assert "CA já existente." in capsys.readouterr().out
    assert cli.main(["show-ca-fingerprint"]) == 0
    assert capsys.readouterr().out.strip() == ca.fingerprint_sha256()


def test_show_ca_fingerprint_wrong_passphrase(
    ops_env: Settings, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    assert cli.main(["init-ca"]) == 0
    capsys.readouterr()
    monkeypatch.setenv("AUDIDASH_CA_PASSPHRASE", "q" * 32)
    assert cli.main(["show-ca-fingerprint"]) == 2
    assert "cannot decrypt CA key" in capsys.readouterr().err


def test_create_enrollment_token_prints_once_and_audits(
    ops_env: Settings, db_session: DbSession, make_user: Any, frozen_clock: Any, capsys: Any
) -> None:
    frozen_clock.current = NOW
    db_session.add(
        User(
            id=uuid.uuid4(),
            username="root",
            password_hash="x",  # noqa: S106
            totp_secret_enc=None,
            role=Role.admin,
            failed_logins=0,
            created_at=NOW,
        )
    )
    db_session.commit()
    assert cli.main(["init-ca"]) == 0
    fingerprint = capsys.readouterr().out.split("SHA-256: ")[1].strip()

    assert cli.main(["create-enrollment-token", "--hours", "2", "--created-by", "root"]) == 0
    out = capsys.readouterr().out
    token = out.splitlines()[0].rsplit(": ", 1)[1]
    assert f"--token={token}" in out
    assert f"--ca-fingerprint {fingerprint}" in out
    assert "audidash enroll --server" in out
    db_session.expire_all()
    row = db_session.scalars(select(EnrollmentToken)).one()
    assert row.expires_at == NOW + timedelta(hours=2)
    entry = db_session.scalars(
        select(AuditEntry).where(AuditEntry.action == "enrollment_token.create")
    ).one()
    assert token not in repr(entry.details)
    assert entry.details["created_by"] == "root"


def test_create_enrollment_token_unknown_user(
    ops_env: Settings, db_session: DbSession, capsys: Any
) -> None:
    assert cli.main(["create-enrollment-token", "--created-by", "ghost"]) == 1
    assert "usuário não encontrado" in capsys.readouterr().err
    assert _count(db_session, EnrollmentToken) == 0


def test_issue_server_cert_cli_writes_files_and_refuses_overwrite(
    ops_env: Settings, tmp_path: Path, capsys: Any
) -> None:
    assert cli.main(["init-ca"]) == 0
    out_cert, out_key = tmp_path / "tls" / "srv.crt", tmp_path / "tls" / "srv.key"
    argv = [
        "issue-server-cert",
        "--host",
        "audi.example.org",
        "--host",
        "10.0.0.5",
        "--out-cert",
        str(out_cert),
        "--out-key",
        str(out_key),
    ]
    assert cli.main(argv) == 0
    if sys.platform != "win32":
        assert stat.S_IMODE(out_key.stat().st_mode) == 0o600
    cert = x509.load_pem_x509_certificate(out_cert.read_bytes())
    key = serialization.load_pem_private_key(out_key.read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()  # type: ignore[union-attr]
    capsys.readouterr()
    assert cli.main(argv) == 1
    assert "já existe" in capsys.readouterr().err
    assert cli.main([*argv, "--force"]) == 0


def test_issue_server_cert_cli_needs_ca(ops_env: Settings, tmp_path: Path, capsys: Any) -> None:
    argv = [
        "issue-server-cert",
        "--host",
        "h",
        "--out-cert",
        str(tmp_path / "c"),
        "--out-key",
        str(tmp_path / "k"),
    ]
    assert cli.main(argv) == 1
    assert "run init-ca" in capsys.readouterr().err


def test_issue_server_cert_properties(tmp_path: Path, frozen_clock: Any) -> None:
    ca = load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))
    cert_pem, key_pem = ca.issue_server_cert(["audi.example.org", "10.0.0.5", "::1"], 30)
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "audi.example.org"
    assert cert.issuer == ca.cert.subject
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["audi.example.org"]
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.5", "::1"]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_cert_sign
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=30, minutes=5)
    key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)
    cert.verify_directly_issued_by(ca.cert)  # signed by the internal CA


@pytest.mark.parametrize("hosts", [[], ["bad host"], ["x;rm"], [""]])
def test_issue_server_cert_rejects_bad_hosts(tmp_path: Path, hosts: list[str]) -> None:
    ca = load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))
    with pytest.raises(CAError):
        ca.issue_server_cert(hosts, 30)


def test_ca_creation_leaves_no_temp_files_and_key_is_private(tmp_path: Path) -> None:
    load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))
    assert sorted(p.name for p in (tmp_path / "ca").iterdir()) == ["ca.crt", "ca.key"]


def test_crash_before_cert_publish_leaves_no_half_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_replace = os.replace

    def crash_on_cert(src: Any, dst: Any) -> None:
        if str(dst).endswith("ca.crt"):
            raise OSError("simulated crash")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", crash_on_cert)
    with pytest.raises(OSError, match="simulated crash"):
        load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))
    monkeypatch.setattr(os, "replace", real_replace)
    assert not (tmp_path / "ca" / "ca.crt").exists()
    assert [p.name for p in (tmp_path / "ca").iterdir() if p.name.endswith(".tmp")] == []
    ca = load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))  # recovers cleanly
    assert load_or_create_ca(tmp_path, SecretStr(PASSPHRASE)).fingerprint_sha256() == (
        ca.fingerprint_sha256()
    )


def _create_in_process(data_dir: str, queue: Any) -> None:
    ca = load_or_create_ca(Path(data_dir), SecretStr(PASSPHRASE))
    queue.put(ca.fingerprint_sha256())


def test_concurrent_creators_converge_on_one_ca(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    procs = [ctx.Process(target=_create_in_process, args=(str(tmp_path), queue)) for _ in range(4)]
    for proc in procs:
        proc.start()
    fingerprints = {queue.get(timeout=60) for _ in procs}
    for proc in procs:
        proc.join(timeout=30)
    assert len(fingerprints) == 1
    loaded = load_or_create_ca(tmp_path, SecretStr(PASSPHRASE))
    assert loaded.fingerprint_sha256() in fingerprints

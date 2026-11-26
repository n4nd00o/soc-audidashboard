"""`audidash-server` administrative command line."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import segno
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as DbSession

from audidash_server import audit, clock
from audidash_server.auth.passwords import WeakPasswordError, hash_password, validate_password
from audidash_server.auth.totp import encrypt_totp_secret, provisioning_uri, totp_secret_new
from audidash_server.ca import (
    CA,
    SERVER_CERT_DEFAULT_DAYS,
    load_existing_ca,
    load_or_create_ca,
    replace_ca,
)
from audidash_server.db import init_db, make_engine
from audidash_server.models import AuditEntry, Role, User
from audidash_server.services import retention
from audidash_server.services.enrollment import create_enrollment_token
from audidash_server.settings import Settings
from audidash_server.web import device_queries as dq

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


def _err(msg: str) -> int:
    print(f"erro: {msg}", file=sys.stderr)
    return 1


def _load_settings() -> Settings:
    settings = Settings()
    if settings.dev_mode:
        # A random per-process secret key would make the stored TOTP secret undecryptable.
        if not os.environ.get("AUDIDASH_SECRET_KEY"):
            raise ValueError("AUDIDASH_SECRET_KEY must be set to create accounts")
        if not settings.database_url:
            raise ValueError("AUDIDASH_DATABASE_URL is missing")
    else:
        settings.validate_for_production()
    return settings


def create_admin(username: str) -> int:
    if not USERNAME_RE.match(username):
        return _err("nome de usuário inválido (3-64 caracteres: letras, números, _ . -).")
    try:
        settings = _load_settings()
    except ValueError as exc:
        return _err(str(exc))

    password = getpass.getpass("Senha: ")
    if getpass.getpass("Confirme a senha: ") != password:
        return _err("as senhas não conferem.")
    try:
        validate_password(password, username)
    except WeakPasswordError as exc:
        return _err(f"senha rejeitada: {exc}")

    engine = make_engine(settings.database_url)
    try:
        if settings.dev_mode and settings.database_url.startswith("sqlite"):
            init_db(engine)  # same dev convenience as the app; production uses Alembic
        with DbSession(engine) as db:
            if db.scalars(select(User).where(User.username == username)).first() is not None:
                return _err(f"o usuário '{username}' já existe; nada foi alterado.")
            secret = totp_secret_new()
            user = User(
                id=uuid.uuid4(),
                username=username,
                password_hash=hash_password(password),
                totp_secret_enc=encrypt_totp_secret(secret, settings.secret_key.get_secret_value()),
                role=Role.admin,
                failed_logins=0,
                created_at=clock.now(),
            )
            db.add(user)
            audit.record(
                db,
                action="user.create",
                actor_user_id=None,
                actor_device_id=None,
                target=username,
                details={"role": Role.admin.value, "via": "cli"},
            )
            db.commit()
    finally:
        engine.dispose()

    uri = provisioning_uri(secret, username)
    print(f"Administrador '{username}' criado.")
    print("Cadastre o segundo fator (TOTP) no aplicativo autenticador:")
    print(uri)
    try:
        segno.make(uri, error="m").terminal(out=sys.stdout, compact=True)
    except (UnicodeEncodeError, OSError):  # e.g. a legacy code page on a redirected stdout
        print("(QR code indisponível neste terminal: use a URI acima.)")
    print("Guarde a chave com segurança: ela não será exibida novamente.")
    return 0


def audit_verify() -> int:
    database_url = Settings().database_url
    if not database_url:
        return _err("AUDIDASH_DATABASE_URL is missing")
    engine = make_engine(database_url)
    try:
        with DbSession(engine) as db:
            bad = audit.verify_chain(db)
            total = db.scalar(select(func.count()).select_from(AuditEntry)) or 0
    except SQLAlchemyError as exc:
        print(f"erro: banco de dados inacessível ({type(exc).__name__})", file=sys.stderr)
        return 2
    finally:
        engine.dispose()
    if bad is not None:
        print(f"audit chain BROKEN at seq {bad}")
        return 1
    print(f"audit chain OK ({total} entries)")
    return 0


def _fail(msg: str, code: int = 2) -> int:
    print(f"erro: {msg}", file=sys.stderr)
    return code


def _ops_settings(*, need_db: bool = True) -> Settings:
    """Settings for operations commands: production-validated unless in dev mode."""
    settings = Settings()
    if not settings.dev_mode:
        settings.validate_for_production()
    elif not os.environ.get("AUDIDASH_CA_PASSPHRASE"):
        raise ValueError("AUDIDASH_CA_PASSPHRASE must be set (dev mode randomises it per process)")
    if need_db and not settings.database_url:
        raise ValueError("AUDIDASH_DATABASE_URL is missing")
    return settings


@contextmanager
def _db(settings: Settings) -> Iterator[DbSession]:
    engine = make_engine(settings.database_url)
    try:
        with DbSession(engine) as db:
            yield db
    finally:
        engine.dispose()


def purge(*, dry_run: bool) -> int:
    try:
        settings = _ops_settings()
        with _db(settings) as db:
            result = retention.purge(db, settings.retention_days, dry_run=dry_run)
            if not dry_run:
                audit.record(
                    db,
                    action="retention.purge",
                    actor_user_id=None,
                    actor_device_id=None,
                    target="retention",
                    details={
                        "cutoff": result.cutoff.isoformat(),
                        "retention_days": settings.retention_days,
                        "runs": result.runs,
                        "findings": result.findings,
                        "events": result.events,
                    },
                )
                db.commit()
    except ValueError as exc:
        return _fail(str(exc))
    except SQLAlchemyError as exc:
        return _fail(f"banco de dados inacessível ({type(exc).__name__})")
    prefix = "[dry-run] seriam removidos" if dry_run else "removidos"
    print(
        f"{prefix}: {result.runs} execuções, {result.findings} achados, "
        f"{result.events} eventos (anteriores a {result.cutoff.isoformat()})"
    )
    return 0


def init_ca(*, force: bool = False) -> int:
    try:
        settings = _ops_settings(need_db=False)
        if force:
            ca, moved = replace_ca(settings.data_dir, settings.ca_passphrase)
            for path in moved:
                print(f"AVISO: arquivo anterior preservado em {path}", file=sys.stderr)
            print(
                "AVISO: uma NOVA CA foi criada; todos os dispositivos inscritos precisam "
                "se reinscrever e o certificado TLS do servidor deve ser reemitido.",
                file=sys.stderr,
            )
            print("CA criada.")
        else:
            existed = load_existing_ca(settings.data_dir, settings.ca_passphrase) is not None
            ca = load_or_create_ca(settings.data_dir, settings.ca_passphrase)
            print("CA já existente." if existed else "CA criada.")
    except (ValueError, OSError) as exc:  # CAError is a ValueError
        return _fail(str(exc))
    print(f"SHA-256: {ca.fingerprint_sha256()}")
    return 0


def _existing_ca(settings: Settings) -> CA | None:
    return load_existing_ca(settings.data_dir, settings.ca_passphrase)


def show_ca_fingerprint() -> int:
    try:
        ca = _existing_ca(_ops_settings(need_db=False))
    except (ValueError, OSError) as exc:
        return _fail(str(exc))
    if ca is None:
        return _fail("CA not initialised — run init-ca", 1)
    print(ca.fingerprint_sha256())
    return 0


def create_token(*, hours: int, created_by: str | None) -> int:
    if not 1 <= hours <= 24 * 30:
        return _fail("--hours deve estar entre 1 e 720", 1)
    try:
        settings = _ops_settings()
        ca = _existing_ca(settings)
        if ca is None:
            return _fail("CA not initialised — run init-ca", 1)
        with _db(settings) as db:
            if created_by is not None:
                owner = db.scalars(
                    select(User).where(User.username == created_by, User.disabled.is_(False))
                ).first()
            else:
                admins = db.scalars(
                    select(User).where(User.role == Role.admin, User.disabled.is_(False))
                ).all()
                if len(admins) > 1:
                    return _fail("vários administradores ativos: informe --created-by USUARIO", 1)
                owner = admins[0] if admins else None
            if owner is None:
                return _fail("usuário não encontrado (use --created-by USUARIO)", 1)
            token = create_enrollment_token(db, owner.id, ttl=timedelta(hours=hours))
            audit.record(
                db,
                action="enrollment_token.create",
                actor_user_id=None,
                actor_device_id=None,
                target="<nome-do-dispositivo>",
                details={"created_by": owner.username, "hours": hours, "via": "cli"},
            )
            db.commit()
    except ValueError as exc:
        return _fail(str(exc))
    except SQLAlchemyError as exc:
        return _fail(f"banco de dados inacessível ({type(exc).__name__})")
    command = dq.enroll_command(
        dashboard_url=settings.public_dashboard_url or dq.PLACEHOLDER_DASHBOARD,
        api_url=settings.public_api_url or dq.PLACEHOLDER_API,
        token=token,
        name="<NOME>",
        ca_fingerprint=ca.fingerprint_sha256(),
    )
    print(f"Token (exibido uma única vez, válido por {hours} h, uso único): {token}")
    print(command)
    return 0


def _write_key(path: Path, data: bytes, *, force: bool) -> None:
    if force:
        path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def issue_server_cert(
    *, hosts: list[str], out_cert: Path, out_key: Path, days: int, force: bool
) -> int:
    try:
        ca = _existing_ca(_ops_settings(need_db=False))
        if ca is None:
            return _fail("CA not initialised — run init-ca", 1)
        if not force and (out_cert.exists() or out_key.exists()):
            return _fail("arquivo de saída já existe (use --force para sobrescrever)", 1)
        cert_pem, key_pem = ca.issue_server_cert(hosts, days)
        out_key.parent.mkdir(parents=True, exist_ok=True)
        out_cert.parent.mkdir(parents=True, exist_ok=True)
        _write_key(out_key, key_pem, force=force)
        out_cert.write_bytes(cert_pem)
    except (ValueError, OSError) as exc:
        return _fail(str(exc))
    print(f"Certificado: {out_cert}")
    print(f"Chave privada (0600): {out_key}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audidash-server", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create an admin account (interactive)")
    admin.add_argument("--username", required=True)
    audit_cmd = sub.add_parser("audit", help="audit log tools")
    audit_sub = audit_cmd.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("verify", help="verify the audit hash chain")
    purge_cmd = sub.add_parser("purge", help="delete runs and findings past the retention window")
    purge_cmd.add_argument("--dry-run", action="store_true", help="only report the counts")
    init_cmd = sub.add_parser("init-ca", help="create the internal CA if it does not exist")
    init_cmd.add_argument(
        "--force", action="store_true", help="start a NEW CA, keeping the old files renamed"
    )
    sub.add_parser("show-ca-fingerprint", help="print the CA certificate SHA-256")
    token_cmd = sub.add_parser("create-enrollment-token", help="issue a single-use enrolment token")
    token_cmd.add_argument("--hours", type=int, default=24)
    token_cmd.add_argument("--created-by", metavar="USERNAME")
    cert_cmd = sub.add_parser("issue-server-cert", help="issue the TLS certificate for the proxy")
    cert_cmd.add_argument("--host", action="append", required=True, dest="hosts")
    cert_cmd.add_argument("--out-cert", type=Path, required=True)
    cert_cmd.add_argument("--out-key", type=Path, required=True)
    cert_cmd.add_argument("--days", type=int, default=SERVER_CERT_DEFAULT_DAYS)
    cert_cmd.add_argument("--force", action="store_true", help="overwrite existing outputs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "create-admin":
        return create_admin(args.username)
    if args.command == "audit" and args.audit_command == "verify":
        return audit_verify()
    if args.command == "purge":
        return purge(dry_run=args.dry_run)
    if args.command == "init-ca":
        return init_ca(force=args.force)
    if args.command == "show-ca-fingerprint":
        return show_ca_fingerprint()
    if args.command == "create-enrollment-token":
        return create_token(hours=args.hours, created_by=args.created_by)
    if args.command == "issue-server-cert":
        return issue_server_cert(
            hosts=args.hosts,
            out_cert=args.out_cert,
            out_key=args.out_key,
            days=args.days,
            force=args.force,
        )
    return 2  # pragma: no cover - argparse enforces the choices


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

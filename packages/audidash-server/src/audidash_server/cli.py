"""`audidash-server` administrative command line."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import uuid

import segno
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from audidash_server import clock
from audidash_server.auth.passwords import WeakPasswordError, hash_password, validate_password
from audidash_server.auth.totp import encrypt_totp_secret, provisioning_uri, totp_secret_new
from audidash_server.db import init_db, make_engine
from audidash_server.models import Role, User
from audidash_server.settings import Settings

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
            db.add(
                User(
                    id=uuid.uuid4(),
                    username=username,
                    password_hash=hash_password(password),
                    totp_secret_enc=encrypt_totp_secret(
                        secret, settings.secret_key.get_secret_value()
                    ),
                    role=Role.admin,
                    failed_logins=0,
                    created_at=clock.now(),
                )
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audidash-server", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create an admin account (interactive)")
    admin.add_argument("--username", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "create-admin":
        return create_admin(args.username)
    return 2  # pragma: no cover - argparse enforces the choices


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

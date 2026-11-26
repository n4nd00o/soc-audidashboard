"""Argon2id password hashing and the password policy."""

from __future__ import annotations

import functools
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 1024  # bound the Argon2 input; anything longer is not a human-typed password
_COMMON_FILE = Path(__file__).with_name("common_passwords.txt")
# Characters commonly appended to a dictionary word ("dragon2024!").
_SUFFIX_CHARS = "0123456789!@#$%&*.,-_+?"

_hasher = PasswordHasher()  # argon2-cffi defaults: Argon2id


class WeakPasswordError(ValueError):
    """Raised with a PT-BR, user-facing explanation when a password violates the policy."""


def hash_password(pw: str) -> str:
    return _hasher.hash(pw)


def verify_password(hash: str, pw: str) -> bool:
    """Constant-time Argon2 verification; False for mismatch or malformed hash."""
    try:
        return _hasher.verify(hash, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hash: str) -> bool:
    """True when the hash was made with weaker parameters than the current defaults."""
    try:
        return _hasher.check_needs_rehash(hash)
    except InvalidHashError:
        return True


@functools.cache
def dummy_hash() -> str:
    """Hash of a random value: verified against for unknown users to equalize timing."""
    return hash_password(secrets.token_urlsafe(32))


@functools.cache
def common_passwords() -> frozenset[str]:
    lines = _COMMON_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.strip().lower() for line in lines if line.strip() and not line.startswith("#")
    )


def _is_repetition(s: str) -> bool:
    """True for "aaaa…", "abcabc…", "passwordpassword": a shorter unit repeated."""
    return s in (s + s)[1:-1]


def validate_password(pw: str, username: str) -> None:
    """Raise WeakPasswordError if `pw` does not satisfy the policy."""
    if len(pw) < MIN_LENGTH:
        raise WeakPasswordError(f"A senha deve ter pelo menos {MIN_LENGTH} caracteres.")
    if len(pw) > MAX_LENGTH:
        raise WeakPasswordError(f"A senha deve ter no máximo {MAX_LENGTH} caracteres.")
    lowered = pw.lower()
    if _is_repetition(lowered):
        raise WeakPasswordError("A senha não pode ser um padrão repetido.")
    name = username.strip().lower()
    if name and name in lowered:
        raise WeakPasswordError("A senha não pode conter o nome de usuário.")
    common = common_passwords()
    base = lowered.rstrip(_SUFFIX_CHARS).lstrip(_SUFFIX_CHARS)
    if lowered in common or base in common:
        raise WeakPasswordError("A senha é comum demais; escolha outra.")

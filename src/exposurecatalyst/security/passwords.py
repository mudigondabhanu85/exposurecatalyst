from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# OWASP-recommended Argon2id parameters (m=19 MiB, t=2, p=1) or stronger.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

# Used to equalise timing when the username does not exist (prevents user enumeration).
_DUMMY_HASH = _hasher.hash("excat-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, *, username: str, min_length: int) -> list[str]:
    problems = []
    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if len(set(password)) < 5:
        problems.append("is too repetitive")
    return problems

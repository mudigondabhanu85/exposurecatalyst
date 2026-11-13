"""Encryption of secrets at rest (Fernet = AES-128-CBC + HMAC-SHA256).

In AWS the Fernet key itself is delivered from Secrets Manager (encrypted with a KMS CMK) as the
EXCAT_ENCRYPTION_KEY env var of the ECS task. A KMS envelope-encryption backend can replace
``SecretBox`` without changing callers.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import structlog
from cryptography.fernet import Fernet, InvalidToken

from exposurecatalyst.config import Settings, get_settings

log = structlog.get_logger(__name__)
_DEV_KEY_FILE = Path(".excat-dev.key")


class SecretBox:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:  # wrong key or tampered ciphertext
            raise ValueError("Unable to decrypt secret (wrong EXCAT_ENCRYPTION_KEY?)") from exc


def _dev_key() -> bytes:
    if _DEV_KEY_FILE.exists():
        return _DEV_KEY_FILE.read_bytes().strip()
    key = Fernet.generate_key()
    fd = os.open(_DEV_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    log.warning("generated_dev_encryption_key", path=str(_DEV_KEY_FILE))
    return key


def build_secret_box(settings: Settings) -> SecretBox:
    if settings.encryption_key is not None:
        return SecretBox(settings.encryption_key.get_secret_value().encode())
    if settings.env == "test":
        return SecretBox(Fernet.generate_key())
    return SecretBox(_dev_key())  # prod without a key is rejected by Settings validation


@lru_cache
def get_secret_box() -> SecretBox:
    return build_secret_box(get_settings())

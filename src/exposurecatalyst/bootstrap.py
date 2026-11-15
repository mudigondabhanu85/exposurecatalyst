"""First-start bootstrap for the Docker deployment (the one-shot ``init`` container).

* Generates missing secrets into protected volumes, consumed through ``EXCAT_<NAME>_FILE`` /
  ``POSTGRES_PASSWORD_FILE``. **Never overwrites** an existing secret file, and never generates one whose value
  is already supplied explicitly (``EXCAT_ENCRYPTION_KEY`` / ``POSTGRES_PASSWORD`` in ``.env``), so existing
  deployments keep their keys and their database password.
* Creates a self-signed certificate for the configured FQDN when no certificate is installed, so HTTPS works
  immediately (the UI shows a "self-signed certificate in use" banner). In self-signed mode, a changed FQDN
  regenerates it; an uploaded or ACME certificate is never touched.

It deliberately does not instantiate :class:`Settings` (whose production guardrails require the very secrets
this creates) and never prints secret values.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import ipaddress
import json
import os
import secrets
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(os.environ.get("EXCAT_STATE_DIR", "/var/lib/excat"))
POSTGRES_GID = 70  # postgres:*-alpine runs as uid/gid 70
SELF_SIGNED_DAYS = 397


@dataclass
class Paths:
    secrets: Path
    db_secret: Path
    certs: Path

    @classmethod
    def from_env(cls) -> Paths:
        return cls(
            secrets=Path(os.environ.get("EXCAT_SECRETS_DIR", ROOT / "secrets")),
            db_secret=Path(os.environ.get("EXCAT_DB_SECRET_DIR", ROOT / "db-secret")),
            certs=Path(os.environ.get("EXCAT_CERTS_DIR", ROOT / "certs")),
        )


def say(msg: str) -> None:
    print(f"[bootstrap] {msg}", flush=True)


def _write_secret(path: Path, value: str, mode: int = 0o600, gid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")
    if gid is not None:
        try:
            os.chown(tmp, -1, gid)
        except PermissionError:
            say(f"warning: could not set group {gid} on {path.name} (run init with group_add: ['{gid}'])")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def ensure_encryption_key(p: Paths) -> str:
    if os.environ.get("EXCAT_ENCRYPTION_KEY"):
        return "encryption key: provided by EXCAT_ENCRYPTION_KEY (kept)"
    f = p.secrets / "encryption_key"
    if f.exists():
        return "encryption key: existing secret kept"
    _write_secret(f, base64.urlsafe_b64encode(os.urandom(32)).decode())
    return "encryption key: generated"


def ensure_db_password(p: Paths) -> str:
    f = p.db_secret / "db_password"
    explicit = os.environ.get("POSTGRES_PASSWORD", "")
    if f.exists():
        if explicit and f.read_text(encoding="utf-8").strip() != explicit:
            return ("database password: existing secret kept — WARNING: it differs from POSTGRES_PASSWORD; "
                    "the database keeps the password it was initialised with")
        return "database password: existing secret kept"
    if explicit:
        _write_secret(f, explicit, 0o640, POSTGRES_GID)
        return "database password: taken from POSTGRES_PASSWORD"
    _write_secret(f, secrets.token_urlsafe(32), 0o640, POSTGRES_GID)
    return "database password: generated"


def ensure_redis_password(p: Paths) -> str:
    conf = p.db_secret / "redis.conf"
    if conf.exists():
        return "redis password: existing secret kept"
    pw = os.environ.get("REDIS_PASSWORD") or secrets.token_urlsafe(32)
    _write_secret(conf, f'requirepass "{pw}"\nsave ""\nappendonly no', 0o640, POSTGRES_GID)
    return "redis password: " + ("taken from REDIS_PASSWORD" if os.environ.get("REDIS_PASSWORD") else "generated")


# ---- self-signed certificate --------------------------------------------------------------------------------

def configured_fqdn() -> str:
    """Same precedence as Settings: non-empty EXCAT_FQDN, else `fqdn` in the YAML config, else localhost."""
    value = os.environ.get("EXCAT_FQDN", "").strip()
    if not value:
        try:
            from exposurecatalyst.config import load_config_file

            value = str(load_config_file().get("fqdn") or "").strip()
        except Exception as exc:  # noqa: BLE001 - a broken config must not block bootstrap; say so
            say(f"warning: could not read the config file ({type(exc).__name__}); using localhost")
            value = ""
    return value.lower().rstrip(".") or "localhost"


def _sans(fqdn: str):
    from cryptography import x509

    names: list = []
    for n in dict.fromkeys([fqdn, "localhost"]):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            names.append(x509.DNSName(n))
    names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    return names


def generate_self_signed(fqdn: str) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn[:64]),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ExposureCatalyst (self-signed)")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=SELF_SIGNED_DAYS))
        .add_extension(x509.SubjectAlternativeName(_sans(fqdn)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def write_active_cert(certs: Path, cert_pem: bytes, key_pem: bytes, meta: dict) -> None:
    """Atomically replace certs/active (previous one kept in certs/previous for rollback)."""
    active, staging, previous = certs / "active", certs / ".staging", certs / "previous"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, mode=0o750)
    (staging / "fullchain.pem").write_bytes(cert_pem)
    fd = os.open(staging / "privkey.pem", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)  # group: proxy
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_pem)
    (staging / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    for f in staging.iterdir():
        os.chmod(f, 0o640)
    if active.exists():
        if previous.exists():
            shutil.rmtree(previous)
        active.rename(previous)
    staging.rename(active)


def read_meta(certs: Path) -> dict:
    try:
        return json.loads((certs / "active" / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ensure_certificate(p: Paths, fqdn: str) -> str:
    active = p.certs / "active"
    meta = read_meta(p.certs)
    have = (active / "fullchain.pem").exists() and (active / "privkey.pem").exists()
    if have and meta.get("mode") != "self-signed":
        return f"certificate: installed ({meta.get('mode', 'uploaded')}) certificate kept"
    if have and meta.get("fqdn") == fqdn:
        return f"certificate: self-signed for {fqdn} kept"
    cert, key = generate_self_signed(fqdn)
    write_active_cert(p.certs, cert, key, {"mode": "self-signed", "fqdn": fqdn,
                                           "created_at": dt.datetime.now(dt.UTC).isoformat()})
    if have:
        return f"certificate: FQDN changed ({meta.get('fqdn')} → {fqdn}); self-signed certificate regenerated"
    return f"certificate: self-signed certificate generated for {fqdn}"


def ensure_backups_dir() -> str | None:
    """backups volume: writable by the `backup` profile (postgres uid/gid 70) and readable by the app."""
    d = Path(os.environ.get("EXCAT_BACKUPS_DIR", ROOT / "backups"))
    if not d.is_dir():
        return None
    try:
        os.chown(d, -1, POSTGRES_GID)
        os.chmod(d, 0o2770)  # noqa: S103  # nosec B103 - owner+group only (no world), setgid keeps group 70
        return "backups directory: ready"
    except PermissionError:
        return None


def run(argv: list[str] | None = None) -> int:
    p = Paths.from_env()
    for d in (p.secrets, p.db_secret, p.certs):
        d.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(PermissionError):
        os.chmod(p.secrets, 0o700)
    steps = [ensure_encryption_key(p), ensure_db_password(p), ensure_redis_password(p),
             ensure_certificate(p, configured_fqdn()), ensure_backups_dir()]
    for s in filter(None, steps):
        say(s)
    say("done")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())

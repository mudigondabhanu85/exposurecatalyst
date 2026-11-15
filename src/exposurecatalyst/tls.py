"""Proxy certificate lifecycle (Settings → Certificates & Domain) and outbound trust.

* install / activate: validated bundle → DB (key Fernet-encrypted) → certs volume (active/, previous kept) →
  hot reload of the proxy through Caddy's admin API on a unix socket shared with the api container (never TCP,
  never the Docker socket) → the served certificate is verified by fingerprint; on mismatch the previous
  certificate is restored automatically.
* rollback: one click back to the previous certificate.
* CSR: private key generated and kept (encrypted) on the server; the signed certificate is matched to it.
* trusted CA bundle: written to the certs volume; outbound clients (CVE sources, integrations, AI SDKs, SMTP)
  trust it through a combined bundle exported as SSL_CERT_FILE / REQUESTS_CA_BUNDLE — only when one exists.
* ACME: the proxy obtains and renews the certificate itself (HTTP-01 or DNS-01); a generated Caddyfile on the
  certs volume persists the mode across proxy restarts.
* expiry alerts at 30/14/7/1 days through the existing SMTP configuration.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
from pathlib import Path
from typing import Any

import httpx
import structlog
from cryptography import x509
from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.bootstrap import write_active_cert
from exposurecatalyst.config import PROJECT_ROOT, Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.models import AppSetting, TlsCertificate, TlsCsr
from exposurecatalyst.security import audit, certs
from exposurecatalyst.security.crypto import get_secret_box

log = structlog.get_logger(__name__)
ADMIN_SOCKET = Path(os.environ.get("EXCAT_PROXY_ADMIN_SOCKET", "/run/caddy-admin/admin.sock"))
PROXY_TLS_ADDR = os.environ.get("EXCAT_PROXY_TLS_ADDRESS", "proxy:8443")
DEFAULT_CADDYFILE = Path(os.environ.get("EXCAT_PROXY_CADDYFILE", PROJECT_ROOT / "docker" / "caddy" / "Caddyfile"))
TRUSTED_CA_KEY = "tls.trusted_ca"
ACME_KEY = "tls.acme"
EXPIRY_KEY = "tls.expiry_alerts"
EXPIRY_THRESHOLDS = (30, 14, 7, 1)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class TlsError(RuntimeError):
    pass


# ---- proxy control -----------------------------------------------------------------------------------------

def proxy_available() -> bool:
    return ADMIN_SOCKET.exists()


def _admin() -> httpx.Client:
    # Host 127.0.0.1: an origin Caddy's admin endpoint accepts on its unix socket.
    return httpx.Client(transport=httpx.HTTPTransport(uds=str(ADMIN_SOCKET)), base_url="http://127.0.0.1",
                        timeout=30, trust_env=False)


def reload_proxy(caddyfile: str) -> None:
    """Load the Caddyfile through the admin API; must-revalidate forces re-reading certificate files even when
    the configuration text is unchanged."""
    if not proxy_available():
        raise TlsError("the proxy admin socket is not available (is the `proxy` service running?)")
    with _admin() as c:
        r = c.post("/load", content=caddyfile.encode(),
                   headers={"Content-Type": "text/caddyfile", "Cache-Control": "must-revalidate"})
    if r.status_code >= 300:
        raise TlsError(f"the proxy rejected the configuration: HTTP {r.status_code} {r.text[:300]}")


def served_fingerprint(server_name: str, address: str = PROXY_TLS_ADDR, timeout: float = 5.0) -> str | None:
    """SHA-256 of the certificate the proxy currently serves for `server_name` (SNI). Only the exact fingerprint
    is compared, so the handshake deliberately skips chain validation."""
    host, _, port = address.rpartition(":")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501 - fingerprint comparison below, not trust
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    except OSError:
        return None
    return hashlib.sha256(der).hexdigest() if der else None


def _wait_served(server_name: str, expected: str, attempts: int = 10) -> bool:
    import time

    for _ in range(attempts):
        if served_fingerprint(server_name) == expected:
            return True
        time.sleep(0.5)
    return False


def current_caddyfile(db: Session, settings: Settings) -> str:
    acme = acme_config(db)
    if settings.features.acme and acme.get("enabled"):
        return render_acme_caddyfile(settings, acme)
    return DEFAULT_CADDYFILE.read_text(encoding="utf-8")


# ---- install / activate / rollback -------------------------------------------------------------------------

def _row_from_bundle(bundle: certs.Bundle, report: certs.Report, source: str, actor: str) -> TlsCertificate:
    info = certs.describe(bundle.leaf)
    return TlsCertificate(
        status="staged", source=source, fingerprint_sha256=info["fingerprint_sha256"], subject=info["subject"],
        issuer=info["issuer"], serial=info["serial"], sans=info["sans"],
        key_type=f"{info['key_type']} {info['key_size'] or ''}".strip(),
        not_before=bundle.leaf.not_valid_before_utc, not_after=bundle.leaf.not_valid_after_utc,
        fullchain_pem=bundle.fullchain_pem().decode(), key_enc=get_secret_box().encrypt(bundle.key_pem().decode()),
        warnings=report.warnings, created_by=actor)


def trusted_roots(db: Session) -> list[x509.Certificate]:
    row = db.get(AppSetting, TRUSTED_CA_KEY)
    if not row or not row.value or not row.value.get("pem"):
        return []
    return x509.load_pem_x509_certificates(row.value["pem"].encode())


def check(db: Session, settings: Settings, bundle: certs.Bundle) -> certs.Report:
    return certs.validate(bundle, settings.fqdn, trusted_roots=trusted_roots(db))


def _write(settings: Settings, row: TlsCertificate) -> None:
    key_pem = get_secret_box().decrypt(row.key_enc).encode()
    write_active_cert(Path(settings.certs_dir), row.fullchain_pem.encode(), key_pem,
                      {"mode": "uploaded", "fqdn": settings.fqdn, "fingerprint": row.fingerprint_sha256,
                       "certificate_id": row.id, "activated_at": utcnow().isoformat()})


def activate(db: Session, settings: Settings, row: TlsCertificate, *, actor: str, request=None,
             action: str = "tls.certificate_installed") -> dict[str, Any]:
    """Write files, hot-reload the proxy, verify the served certificate; restore the previous files on failure."""
    certs_dir = Path(settings.certs_dir)
    backup = certs_dir / ".rollback"
    if backup.exists():
        shutil.rmtree(backup)
    if (certs_dir / "active").exists():
        shutil.copytree(certs_dir / "active", backup)
    if row.id is None:
        db.add(row)
        db.flush()
    try:
        _write(settings, row)
        reload_proxy(current_caddyfile(db, settings))
        server_name = settings.fqdn or "localhost"
        if not _wait_served(server_name, row.fingerprint_sha256):
            raise TlsError("the proxy did not start serving the new certificate")
    except Exception as exc:
        if backup.exists():  # put the previous certificate back exactly as it was
            if (certs_dir / "active").exists():
                shutil.rmtree(certs_dir / "active")
            shutil.copytree(backup, certs_dir / "active")
            with contextlib.suppress(TlsError):
                reload_proxy(current_caddyfile(db, settings))
        row.status = "failed"
        audit.record(db, action, actor_username=actor, request=request, outcome="failure", target_type="certificate",
                     target_id=row.id, details={"fingerprint": row.fingerprint_sha256, "error": str(exc)[:300]})
        db.commit()
        raise TlsError(f"activation failed, previous certificate restored: {exc}") from exc
    for old in db.scalars(select(TlsCertificate).where(TlsCertificate.status.in_(("active", "previous")),
                                                       TlsCertificate.id != row.id)):
        old.status = "previous" if old.status == "active" else "archived"
    row.status, row.activated_at = "active", utcnow()
    audit.record(db, action, actor_username=actor, request=request, target_type="certificate", target_id=row.id,
                 details={"fingerprint": row.fingerprint_sha256, "subject": row.subject, "sans": row.sans,
                          "not_after": row.not_after.isoformat(), "source": row.source})
    db.commit()
    return {"activated": True, "certificate_id": row.id, "fingerprint": row.fingerprint_sha256}


def install(db: Session, settings: Settings, bundle: certs.Bundle, *, source: str, actor: str,
            request=None) -> dict[str, Any]:
    report = check(db, settings, bundle)
    if not report.ok:
        audit.record(db, "tls.certificate_rejected", actor_username=actor, request=request, outcome="failure",
                     details={"errors": report.errors[:5], "subject": report.info.get("subject")})
        db.commit()
        raise certs.CertError("; ".join(report.errors))
    row = _row_from_bundle(bundle, report, source, actor)
    return {**activate(db, settings, row, actor=actor, request=request), "warnings": report.warnings}


def rollback(db: Session, settings: Settings, *, actor: str, request=None) -> dict[str, Any]:
    prev = db.scalar(select(TlsCertificate).where(TlsCertificate.status == "previous")
                     .order_by(TlsCertificate.activated_at.desc()))
    if prev is not None:
        return activate(db, settings, prev, actor=actor, request=request, action="tls.certificate_rolled_back")
    return _rollback_files(db, settings, actor=actor, request=request)


def _rollback_files(db: Session, settings: Settings, *, actor: str, request=None) -> dict[str, Any]:
    """Previous certificate that only exists on the certs volume (e.g. the generated self-signed one): swap the
    active/ and previous/ directories, reload, verify; swap back on failure."""
    root = Path(settings.certs_dir)
    active, previous, swap = root / "active", root / "previous", root / ".swap"
    if not (previous / "fullchain.pem").is_file() or not (previous / "privkey.pem").is_file():
        raise TlsError("there is no previous certificate to roll back to")
    expected = certs.fingerprint(x509.load_pem_x509_certificates((previous / "fullchain.pem").read_bytes())[0])
    meta = {}
    with contextlib.suppress(OSError, ValueError):
        meta = json.loads((previous / "meta.json").read_text(encoding="utf-8"))

    def swap_dirs() -> None:
        if swap.exists():
            shutil.rmtree(swap)
        active.rename(swap)
        previous.rename(active)
        swap.rename(previous)

    swap_dirs()
    try:
        reload_proxy(current_caddyfile(db, settings))
        if not _wait_served(settings.fqdn or "localhost", expected):
            raise TlsError("the proxy did not start serving the previous certificate")
    except Exception as exc:
        swap_dirs()
        with contextlib.suppress(TlsError):
            reload_proxy(current_caddyfile(db, settings))
        raise TlsError(f"rollback failed, current certificate kept: {exc}") from exc
    for row in db.scalars(select(TlsCertificate).where(TlsCertificate.status == "active")):
        row.status = "previous"
    audit.record(db, "tls.certificate_rolled_back", actor_username=actor, request=request,
                 target_type="certificate", details={"fingerprint": expected, "mode": meta.get("mode", "uploaded")})
    db.commit()
    return {"activated": True, "certificate_id": meta.get("certificate_id"), "fingerprint": expected,
            "mode": meta.get("mode", "uploaded")}


# ---- CSR ---------------------------------------------------------------------------------------------------

def create_csr(db: Session, *, common_name: str, sans: list[str], key_type: str, subject: dict[str, str | None],
               actor: str, request=None) -> TlsCsr:
    key = certs.generate_key(key_type)
    csr_pem = certs.build_csr(key, common_name, sans, **subject)
    row = TlsCsr(status="pending", common_name=common_name, sans=sans, key_type=key_type,
                 public_key_id=certs.public_key_id(key.public_key()), csr_pem=csr_pem.decode(),
                 key_enc=get_secret_box().encrypt(certs.key_pem(key).decode()), created_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, "tls.csr_created", actor_username=actor, request=request, target_type="csr", target_id=row.id,
                 details={"common_name": common_name, "sans": sans, "key_type": key_type})
    db.commit()
    return row


def complete_csr(db: Session, settings: Settings, csr: TlsCsr, cert_pem: bytes, chain_pem: bytes | None, *,
                 actor: str, request=None) -> dict[str, Any]:
    if csr.status != "pending":
        raise certs.CertError("this CSR is no longer pending")
    found = certs._dedupe(certs._certs_from_pem(cert_pem) + certs._certs_from_pem(chain_pem or b""))
    leaf = next((c for c in found if certs.public_key_id(c.public_key()) == csr.public_key_id), None)
    if leaf is None:
        raise certs.CertError("the signed certificate does not match this CSR's private key")
    key = certs._load_key(get_secret_box().decrypt(csr.key_enc).encode(), None)
    bundle = certs.Bundle(leaf, certs._order_chain(leaf, [c for c in found if c is not leaf]), key)
    result = install(db, settings, bundle, source="csr", actor=actor, request=request)
    csr.status, csr.completed_at = "completed", utcnow()
    db.commit()
    return result


# ---- trusted CA bundle (outbound) --------------------------------------------------------------------------

def trusted_ca_file(settings: Settings) -> Path:
    return Path(settings.certs_dir) / "trusted-ca" / "bundle.pem"


def set_trusted_ca(db: Session, settings: Settings, pem: bytes | None, *, actor: str, request=None) -> dict:
    row = db.get(AppSetting, TRUSTED_CA_KEY)
    path = trusted_ca_file(settings)
    if pem is None:
        if row is not None:
            db.delete(row)
        if path.exists():
            path.unlink()
        audit.record(db, "tls.trusted_ca_removed", actor_username=actor, request=request)
        db.commit()
        apply_trusted_ca(settings, force=True)
        return {"certificates": []}
    cas = certs.parse_ca_bundle(pem)
    text = "".join(c.public_bytes(certs.serialization.Encoding.PEM).decode() for c in cas)
    subjects = [c.subject.rfc4514_string() for c in cas]
    value = {"pem": text, "subjects": subjects, "updated_at": utcnow().isoformat()}
    if row is None:
        db.add(AppSetting(key=TRUSTED_CA_KEY, value=value, updated_by=actor))
    else:
        row.value, row.updated_by = value, actor
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    audit.record(db, "tls.trusted_ca_updated", actor_username=actor, request=request,
                 details={"subjects": subjects})
    db.commit()
    apply_trusted_ca(settings, force=True)
    return {"certificates": subjects}


_ca_state: dict[str, Any] = {"mtime": None}


def apply_trusted_ca(settings: Settings, *, force: bool = False) -> None:
    """Export SSL_CERT_FILE / REQUESTS_CA_BUNDLE = public roots + trusted CA bundle while one exists (httpx,
    SDKs and OpenSSL honour them). Cheap mtime check, so it is safe to call before every outbound client."""
    explicit = os.environ.get("EXCAT_CA_BUNDLE", "").strip()
    src = Path(explicit) if explicit else trusted_ca_file(settings)
    try:
        mtime = src.stat().st_mtime
    except OSError:
        mtime = None
    if not force and mtime == _ca_state["mtime"]:
        return
    _ca_state["mtime"] = mtime
    if mtime is None:
        if _ca_state.get("exported"):
            for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
                os.environ.pop(k, None)
            _ca_state["exported"] = False
        return
    import tempfile

    import certifi

    combined = Path(tempfile.gettempdir()) / "excat-ca-bundle.pem"
    combined.write_bytes(Path(certifi.where()).read_bytes() + b"\n" + src.read_bytes())
    os.environ["SSL_CERT_FILE"] = os.environ["REQUESTS_CA_BUNDLE"] = str(combined)
    _ca_state["exported"] = True


# ---- ACME --------------------------------------------------------------------------------------------------

def acme_config(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, ACME_KEY)
    return dict(row.value) if row and row.value else {"enabled": False}


def render_acme_caddyfile(settings: Settings, cfg: dict[str, Any]) -> str:
    """Caddyfile for ACME mode: Caddy obtains/renews the certificate for the FQDN itself."""
    if not settings.fqdn or settings.fqdn == "localhost":
        raise TlsError("ACME needs a public FQDN (set fqdn)")
    issuer = ["\t\tissuer acme {"]
    if cfg.get("directory_url"):
        issuer.append(f"\t\t\tdir {cfg['directory_url']}")
    issuer.append(f"\t\t\temail {cfg['email']}")
    if cfg.get("challenge") == "dns-01":
        provider = cfg.get("dns_provider")
        if provider == "cloudflare":
            issuer.append("\t\t\tdns cloudflare {env.EXCAT_ACME_CLOUDFLARE_API_TOKEN}")
        elif provider == "route53":
            issuer.append("\t\t\tdns route53")
        else:
            raise TlsError("DNS-01 needs dns_provider route53 or cloudflare")
        issuer.append("\t\t\tdisable_http_challenge\n\t\t\tdisable_tlsalpn_challenge")
    else:
        issuer.append("\t\t\tdisable_tlsalpn_challenge")
    if trusted_ca_file(settings).is_file():  # internal ACME CA (step-ca, …): trust the uploaded CA bundle
        issuer.append("\t\t\ttrusted_roots /certs/trusted-ca/bundle.pem")
    issuer.append("\t\t}")
    https_port = 8443
    return f"""# Generated by ExposureCatalyst (Settings → Certificates & Domain, ACME mode). Do not edit.
{{
	admin unix//run/caddy-admin/admin.sock|0660
	http_port 8080
	https_port {https_port}
	servers {{
		protocols h1 h2
		trusted_proxies static {{$EXCAT_TRUSTED_PROXIES:private_ranges}}
	}}
	log {{
		output stdout
		format json
	}}
}}

http://:8080 {{
	handle /healthz {{
		respond "ok" 200
	}}
	handle {{
		redir https://{{host}}{{$EXCAT_HTTPS_PORT_SUFFIX}}{{uri}} 308
	}}
}}

{settings.fqdn}:{https_port} {{
	tls {{
		protocols tls1.2 tls1.3
{chr(10).join(issuer)}
	}}
	encode zstd gzip
	request_body {{
		max_size 60MB
	}}
	@assets path /assets/*
	handle @assets {{
		root * /srv
		header Cache-Control "public, max-age=31536000, immutable"
		header X-Content-Type-Options nosniff
		file_server
	}}
	handle {{
		reverse_proxy api:8000 {{
			health_uri /api/health/live
			health_interval 15s
		}}
	}}
}}
"""


def set_acme(db: Session, settings: Settings, cfg: dict[str, Any], *, actor: str, request=None) -> dict[str, Any]:
    enabled = bool(cfg.get("enabled"))
    clean: dict[str, Any] = {"enabled": enabled}
    if enabled:
        email = str(cfg.get("email") or "")
        if not EMAIL_RE.match(email):
            raise TlsError("a contact email is required for ACME")
        challenge = cfg.get("challenge") or "http-01"
        if challenge not in ("http-01", "dns-01"):
            raise TlsError("challenge must be http-01 or dns-01")
        directory = str(cfg.get("directory_url") or "")
        if directory and not directory.startswith("https://"):
            raise TlsError("the ACME directory URL must be https")
        clean |= {"email": email, "challenge": challenge, "dns_provider": cfg.get("dns_provider"),
                  "directory_url": directory or None}
    caddyfile = render_acme_caddyfile(settings, clean) if enabled else DEFAULT_CADDYFILE.read_text("utf-8")
    persisted = Path(settings.certs_dir) / "proxy" / "Caddyfile"
    if enabled:
        persisted.parent.mkdir(parents=True, exist_ok=True)
        persisted.write_text(caddyfile, encoding="utf-8")
    elif persisted.exists():
        persisted.unlink()
    reload_proxy(caddyfile)
    row = db.get(AppSetting, ACME_KEY)
    if row is None:
        db.add(AppSetting(key=ACME_KEY, value=clean, updated_by=actor))
    else:
        row.value, row.updated_by = clean, actor
    meta_file = Path(settings.certs_dir) / "active" / "meta.json"
    if meta_file.exists():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        meta["acme"] = enabled
        meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    audit.record(db, "tls.acme_updated", actor_username=actor, request=request,
                 details={k: v for k, v in clean.items() if k != "email"} | {"email_set": bool(clean.get("email"))})
    db.commit()
    return clean


# ---- expiry alerts -----------------------------------------------------------------------------------------

def expiry_alerts(db: Session, settings: Settings, *, now: dt.datetime | None = None, send=None) -> list[int]:
    """Email admins once per threshold (30/14/7/1 days) for the active uploaded certificate."""
    now = now or utcnow()
    row = db.scalar(select(TlsCertificate).where(TlsCertificate.status == "active"))
    if row is None:
        return []
    days = (row.not_after - now if row.not_after.tzinfo else row.not_after.replace(tzinfo=dt.UTC) - now).days
    due = [t for t in EXPIRY_THRESHOLDS if days <= t]
    if not due:
        return []
    state_row = db.get(AppSetting, EXPIRY_KEY)
    state = dict(state_row.value) if state_row and state_row.value else {}
    sent = set(state.get(row.fingerprint_sha256, []))
    threshold = min(due)
    if threshold in sent:
        return []
    (send or _email_admins)(db, settings, row, days)
    state[row.fingerprint_sha256] = sorted(sent | set(due))
    if state_row is None:
        db.add(AppSetting(key=EXPIRY_KEY, value=state, updated_by="system"))
    else:
        state_row.value = state
    audit.record(db, "tls.expiry_alert", actor_username="system", target_type="certificate", target_id=row.id,
                 details={"days_left": days, "threshold": threshold})
    db.commit()
    return [threshold]


def _email_admins(db: Session, settings: Settings, row: TlsCertificate, days: int) -> None:
    from email.message import EmailMessage

    from exposurecatalyst.advisories.delivery import send
    from exposurecatalyst.api.smtp import load_config
    from exposurecatalyst.models import User
    from exposurecatalyst.security.rbac import Permission, user_permissions

    cfg = load_config(db)
    to = sorted({u.email for u in db.scalars(select(User).where(User.is_active.is_(True)))
                 if u.email and str(Permission.SETTINGS_MANAGE) in user_permissions(u)})
    if cfg is None or not to:
        log.warning("tls_expiry_alert_not_emailed", days_left=days, reason="no SMTP" if cfg is None else "no admins")
        return
    msg = EmailMessage()
    msg["Subject"] = f"[ExposureCatalyst] TLS certificate expires in {max(days, 0)} day(s)"
    msg["From"], msg["To"] = cfg.from_address, ", ".join(to)
    msg.set_content(f"The certificate for {', '.join(row.sans)} expires on {row.not_after:%Y-%m-%d} "
                    f"({max(days, 0)} days).\n\nInstall a renewed certificate: "
                    f"{settings.public_url.rstrip('/')}/settings/certificates\n")
    send(msg, to, cfg, settings)

"""Deployment state shared by the API: FQDN change detection, admin banners, certificate status and the
first-run setup token. Everything here is additive: with no FQDN, no certs volume and existing users, nothing is
shown and nothing changes.
"""

from __future__ import annotations

import hmac
import json
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import AppSetting, User
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box

log = structlog.get_logger(__name__)
DOMAIN_KEY = "deployment.domain"
DOMAIN_BANNER_KEY = "deployment.banner.domain_changed"
SETUP_KEY = "setup.token"
SETUP_PENDING_KEY = "setup.pending"


# ---- FQDN / public URL -------------------------------------------------------------------------------------

def derived_urls(settings: Settings) -> dict[str, str]:
    """Every URL that depends on the public URL (shown with copy buttons in Certificates & Domain)."""
    from exposurecatalyst.sso.saml import METADATA_PATH

    base = settings.public_url.rstrip("/")
    return {
        "Application": base,
        "SAML SP entity ID (default)": f"{base}{METADATA_PATH}",
        "SAML ACS URL": f"{base}/api/auth/saml/acs",
        "SAML SP metadata": f"{base}{METADATA_PATH}",
        "OIDC redirect URI": f"{base}/api/auth/oidc/callback",
        "SCIM base URL": f"{base}/scim/v2",
        "Documentation": f"{base}/docs/",
        "Advisory links": f"{base}/advisories/<id>",
    }


def record_domain(db: Session, settings: Settings) -> bool:
    """Called at API startup. Remembers the public URL; when it changed since the last start, raises the
    "Domain changed" admin banner and audits it. Returns True when a change was detected."""
    current = {"fqdn": settings.fqdn, "public_url": settings.public_url.rstrip("/")}
    row = db.get(AppSetting, DOMAIN_KEY)
    previous = dict(row.value) if row and row.value else None
    if previous and previous.get("public_url") == current["public_url"]:
        return False
    if row is None:
        db.add(AppSetting(key=DOMAIN_KEY, value={**current, "since": utcnow().isoformat()}, updated_by="system"))
    else:
        row.value, row.updated_by = {**current, "since": utcnow().isoformat()}, "system"
    changed = previous is not None
    if changed:
        banner = {"from": previous.get("public_url"), "to": current["public_url"], "at": utcnow().isoformat(),
                  "dismissed": False}
        b = db.get(AppSetting, DOMAIN_BANNER_KEY)
        if b is None:
            db.add(AppSetting(key=DOMAIN_BANNER_KEY, value=banner, updated_by="system"))
        else:
            b.value = banner
        audit.record(db, "system.domain_changed", actor_username="system", target_type="settings",
                     target_id="domain", details={"from": banner["from"], "to": banner["to"]})
        log.warning("domain_changed", previous=banner["from"], current=banner["to"],
                    action="update Okta (download new SP metadata), DNS and the TLS certificate")
    try:
        db.commit()
    except IntegrityError:  # another worker recorded it first
        db.rollback()
    return changed


# ---- certificate status ------------------------------------------------------------------------------------

def certificate_status(settings: Settings) -> dict[str, Any] | None:
    """Active proxy certificate summary from the certs volume, or None outside Docker."""
    active = Path(settings.certs_dir) / "active"
    cert_file = active / "fullchain.pem"
    if not cert_file.is_file():
        return None
    try:
        meta = json.loads((active / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    out: dict[str, Any] = {"mode": meta.get("mode", "uploaded")}
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert = x509.load_pem_x509_certificates(cert_file.read_bytes())[0]
        try:
            sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = sans.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        not_after = cert.not_valid_after_utc
        out |= {"subject": cert.subject.rfc4514_string(), "not_after": not_after.isoformat(),
                "days_left": (not_after - utcnow()).days, "sans": names,
                "covers_fqdn": bool(settings.fqdn) and _san_matches(settings.fqdn or "", names)}
    except Exception as exc:  # noqa: BLE001 - status is informational
        out["error"] = type(exc).__name__
    return out


def _san_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host or (n.startswith("*.") and host.count(".") >= 2 and host.split(".", 1)[1] == n[2:]):
            return True
    return False


# ---- banners -----------------------------------------------------------------------------------------------

def banners(db: Session, settings: Settings, *, admin: bool) -> list[dict[str, Any]]:
    if not admin:
        return []
    out: list[dict[str, Any]] = []
    b = db.get(AppSetting, DOMAIN_BANNER_KEY)
    if b and b.value and not b.value.get("dismissed"):
        out.append({"id": "domain_changed", "level": "warning", "dismissible": True,
                    "title": "Domain changed",
                    "message": f"The public URL changed from {b.value.get('from')} to {b.value.get('to')}. Update "
                               "Okta (download the new SP metadata), DNS, and the TLS certificate.",
                    "link": "/settings/certificates"})
    cert = certificate_status(settings)
    if cert and cert.get("mode") == "self-signed":
        out.append({"id": "self_signed", "level": "info", "dismissible": False,
                    "title": "Self-signed certificate in use",
                    "message": "Browsers will warn until a trusted certificate is installed "
                               "(Settings → Certificates & Domain).", "link": "/settings/certificates"})
    elif cert and isinstance(cert.get("days_left"), int) and cert["days_left"] <= 30:
        out.append({"id": "cert_expiry", "level": "warning" if cert["days_left"] > 7 else "error",
                    "dismissible": False, "title": "TLS certificate expires soon",
                    "message": f"The certificate expires in {max(cert['days_left'], 0)} day(s).",
                    "link": "/settings/certificates"})
    if cert and settings.fqdn and cert.get("covers_fqdn") is False and cert.get("mode") != "self-signed":
        out.append({"id": "san_mismatch", "level": "error", "dismissible": False,
                    "title": "Certificate does not match the domain",
                    "message": f"The installed certificate does not cover {settings.fqdn}.",
                    "link": "/settings/certificates"})
    return out


def dismiss(db: Session, banner_id: str) -> bool:
    if banner_id != "domain_changed":
        return False
    b = db.get(AppSetting, DOMAIN_BANNER_KEY)
    if b is None or not b.value:
        return False
    b.value = {**b.value, "dismissed": True}
    return True


# ---- first-run setup token ---------------------------------------------------------------------------------

def setup_required(db: Session) -> bool:
    """The wizard is offered only to an empty installation (no users at all)."""
    return (db.scalar(select(func.count()).select_from(User)) or 0) == 0


def ensure_setup_token(db: Session, settings: Settings) -> str | None:
    """On an empty installation, make sure a valid token exists and return it (to be printed to the logs).
    Stored Fernet-encrypted so every API process can print the same token; deleted once used."""
    if not setup_required(db):
        row = db.get(AppSetting, SETUP_KEY)
        if row is not None:
            db.delete(row)
            db.commit()
        return None
    row = db.get(AppSetting, SETUP_KEY)
    box = get_secret_box()
    if row and row.value and as_utc_iso(row.value.get("expires_at")) > utcnow():
        return box.decrypt(row.value["token_enc"])
    token = secrets.token_urlsafe(24)
    value = {"token_enc": box.encrypt(token),
             "expires_at": (utcnow() + timedelta(hours=settings.setup_token_hours)).isoformat()}
    if row is None:
        db.add(AppSetting(key=SETUP_KEY, value=value, updated_by="system"))
    else:
        row.value = value
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        row = db.get(AppSetting, SETUP_KEY)
        return box.decrypt(row.value["token_enc"]) if row else None
    return token


def check_setup_token(db: Session, token: str) -> bool:
    row = db.get(AppSetting, SETUP_KEY)
    if not row or not row.value or as_utc_iso(row.value.get("expires_at")) <= utcnow():
        return False
    expected = get_secret_box().decrypt(row.value["token_enc"])
    return hmac.compare_digest(expected.encode(), token.strip().encode())


def consume_setup_token(db: Session) -> None:
    for key in (SETUP_KEY, SETUP_PENDING_KEY):
        row = db.get(AppSetting, key)
        if row is not None:
            db.delete(row)


def as_utc_iso(value: Any):
    from datetime import datetime

    try:
        return as_utc(datetime.fromisoformat(str(value)))
    except (TypeError, ValueError):
        return utcnow() - timedelta(seconds=1)


def print_setup_token(token: str, settings: Settings) -> None:
    """Deliberately a plain stdout block (not a structured log field) so operators can find it in
    `docker compose logs api`. The token alone cannot create an account: the wizard also requires MFA."""
    url = settings.public_url.rstrip("/") + "/setup"
    print("\n" + "=" * 78 + "\n ExposureCatalyst first-run setup\n"
          f"   Open {url} and enter this one-time setup token:\n\n      {token}\n\n"
          f"   It expires in {settings.setup_token_hours} h or when the first administrator is created.\n"
          + "=" * 78 + "\n", flush=True)

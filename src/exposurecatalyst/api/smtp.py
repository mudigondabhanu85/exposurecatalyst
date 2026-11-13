"""Settings → SMTP. Password is Fernet-encrypted at rest and never returned to the UI."""

from __future__ import annotations

from email.message import EmailMessage
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from exposurecatalyst.advisories.delivery import SmtpConfig, send, validate_smtp_host
from exposurecatalyst.advisories.render import LOGO_CID, logo_bytes
from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import AppSetting
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.security.rbac import Permission
from exposurecatalyst.security.ssrf import UnsafeURLError

router = APIRouter(prefix="/api/settings/smtp", tags=["settings"])
KEY = "smtp"


class SmtpIn(BaseModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port: int = Field(587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str | None = Field(None, max_length=256)
    password: str | None = Field(None, max_length=512, description="Omit to keep the stored password")
    clear_password: bool = False
    from_address: EmailStr
    from_name: str | None = Field("ExposureCatalyst", max_length=100)
    reply_to: EmailStr | None = None


class SmtpOut(BaseModel):
    configured: bool
    host: str | None = None
    port: int | None = None
    security: str | None = None
    username: str | None = None
    has_password: bool = False
    from_address: str | None = None
    from_name: str | None = None
    reply_to: str | None = None


def load_config(db: Session) -> SmtpConfig | None:
    row = db.get(AppSetting, KEY)
    if row is None or not row.value:
        return None
    v = row.value
    pw = get_secret_box().decrypt(v["password_enc"]) if v.get("password_enc") else None
    return SmtpConfig(host=v["host"], port=v["port"], security=v["security"], username=v.get("username"),
                      password=pw, from_address=v["from_address"], from_name=v.get("from_name"),
                      reply_to=v.get("reply_to"))


@router.get("", response_model=SmtpOut)
def get_smtp(_: Principal = Depends(require(Permission.SETTINGS_MANAGE)), db: Session = Depends(get_db)) -> SmtpOut:
    row = db.get(AppSetting, KEY)
    if row is None or not row.value:
        return SmtpOut(configured=False)
    v = row.value
    return SmtpOut(configured=True, host=v["host"], port=v["port"], security=v["security"],
                   username=v.get("username"), has_password=bool(v.get("password_enc")),
                   from_address=v["from_address"], from_name=v.get("from_name"), reply_to=v.get("reply_to"))


@router.put("", response_model=SmtpOut)
def put_smtp(body: SmtpIn, request: Request, p: Principal = Depends(require(Permission.SETTINGS_MANAGE)),
             db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> SmtpOut:
    if body.security == "none" and not settings.smtp_allow_plaintext:
        raise HTTPException(422, "Plaintext SMTP is disabled; use STARTTLS or SSL/TLS")
    try:
        validate_smtp_host(body.host, body.port, settings)
    except UnsafeURLError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = db.get(AppSetting, KEY)
    old = dict(row.value) if row and row.value else {}
    pw_enc = old.get("password_enc")
    if body.clear_password:
        pw_enc = None
    elif body.password:
        pw_enc = get_secret_box().encrypt(body.password)
    value = {"host": body.host.lower(), "port": body.port, "security": body.security, "username": body.username,
             "password_enc": pw_enc, "from_address": str(body.from_address), "from_name": body.from_name,
             "reply_to": str(body.reply_to) if body.reply_to else None}
    if row is None:
        db.add(AppSetting(key=KEY, value=value, updated_by=p.user.username))
    else:
        row.value, row.updated_by = value, p.user.username
    audit.record(db, "settings.smtp_updated", actor=p.user, request=request, target_type="settings", target_id=KEY,
                 details={**{k: v for k, v in value.items() if k != "password_enc"},
                          "password_changed": bool(body.password)})
    db.commit()
    return get_smtp(p, db)


class TestIn(BaseModel):
    to: EmailStr


@router.post("/test")
def test_smtp(body: TestIn, request: Request, p: Principal = Depends(require(Permission.SETTINGS_MANAGE)),
              db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> dict:
    cfg = load_config(db)
    if cfg is None:
        raise HTTPException(409, "SMTP is not configured")
    msg = EmailMessage()
    msg["Subject"] = "ExposureCatalyst SMTP test"
    msg["From"] = cfg.from_address
    msg["To"] = str(body.to)
    msg.set_content("This is a test message from ExposureCatalyst. SMTP delivery is working.")
    msg.add_alternative(
        '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #D5DBE4;">'
        '<tr><td style="padding:16px 20px;border-bottom:4px solid #E8541A;">'
        f'<img src="cid:{LOGO_CID}" width="211" height="40" alt="ExposureCatalyst" style="display:block;border:0;" />'
        '</td></tr><tr><td style="padding:16px 20px;font-family:Inter,Arial,sans-serif;font-size:14px;color:#0B1B33;">'
        "SMTP delivery is working.</td></tr></table>",
        subtype="html")
    msg.get_payload()[1].add_related(logo_bytes(), maintype="image", subtype="png", cid=f"<{LOGO_CID}>",
                                     filename="exposurecatalyst.png", disposition="inline")
    try:
        send(msg, [str(body.to)], cfg, settings)
    except Exception as exc:  # noqa: BLE001 - report a sanitized reason to the admin
        audit.record(db, "settings.smtp_test", actor=p.user, request=request, outcome="failure",
                     details={"to": str(body.to), "error": type(exc).__name__})
        db.commit()
        raise HTTPException(502, f"SMTP test failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    audit.record(db, "settings.smtp_test", actor=p.user, request=request, details={"to": str(body.to)})
    db.commit()
    return {"sent": True}

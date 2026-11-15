"""Settings → SMTP: SMTP relay (password or Microsoft 365 OAuth2) or the Amazon SES API.

The SMTP password and the Entra ID client secret are Fernet-encrypted at rest and never returned to the UI.
"""

from __future__ import annotations

from email.message import EmailMessage
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, model_validator
from sqlalchemy.orm import Session

from exposurecatalyst.advisories.delivery import (
    M365_SMTP_HOST,
    SES_REGION_RE,
    TENANT_RE,
    SmtpConfig,
    send,
    validate_smtp_host,
)
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
    provider: Literal["smtp", "ses_api"] = "smtp"
    auth: Literal["password", "oauth2_m365"] = "password"
    host: str | None = Field(None, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port: int = Field(587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str | None = Field(None, max_length=256)
    password: str | None = Field(None, max_length=512, description="Omit to keep the stored password")
    clear_password: bool = False
    m365_tenant_id: str | None = Field(None, max_length=100)
    m365_client_id: str | None = Field(None, max_length=100)
    m365_client_secret: str | None = Field(None, max_length=512, description="Omit to keep the stored secret")
    m365_cloud: Literal["global", "usgov"] = "global"
    ses_region: str | None = Field(None, max_length=32)
    ses_configuration_set: str | None = Field(None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    from_address: EmailStr
    from_name: str | None = Field("ExposureCatalyst", max_length=100)
    reply_to: EmailStr | None = None

    @model_validator(mode="after")
    def _per_method(self) -> SmtpIn:
        if self.provider == "ses_api":
            if not self.ses_region or not SES_REGION_RE.match(self.ses_region):
                raise ValueError("Amazon SES needs a region such as us-east-1")
            return self
        if not self.host:
            raise ValueError("SMTP host is required")
        if self.auth == "oauth2_m365":
            if not self.m365_tenant_id or not TENANT_RE.match(self.m365_tenant_id):
                raise ValueError("Microsoft 365 OAuth2 needs the directory (tenant) ID")
            if not self.m365_client_id:
                raise ValueError("Microsoft 365 OAuth2 needs the application (client) ID")
            if not self.username:
                raise ValueError("Microsoft 365 OAuth2 needs the sending mailbox (username)")
            if self.security == "none":
                raise ValueError("Microsoft 365 OAuth2 requires STARTTLS or SSL/TLS")
        return self


class SmtpOut(BaseModel):
    configured: bool
    provider: str = "smtp"
    auth: str = "password"
    m365_tenant_id: str | None = None
    m365_client_id: str | None = None
    has_m365_client_secret: bool = False
    m365_cloud: str = "global"
    ses_region: str | None = None
    ses_configuration_set: str | None = None
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
    box = get_secret_box()
    pw = box.decrypt(v["password_enc"]) if v.get("password_enc") else None
    secret = box.decrypt(v["m365_client_secret_enc"]) if v.get("m365_client_secret_enc") else None
    return SmtpConfig(host=v.get("host") or "", port=v.get("port") or 587, security=v.get("security") or "starttls",
                      username=v.get("username"), password=pw, from_address=v["from_address"],
                      from_name=v.get("from_name"), reply_to=v.get("reply_to"),
                      provider=v.get("provider", "smtp"), auth=v.get("auth", "password"),
                      m365_tenant_id=v.get("m365_tenant_id"), m365_client_id=v.get("m365_client_id"),
                      m365_client_secret=secret, m365_cloud=v.get("m365_cloud", "global"),
                      ses_region=v.get("ses_region"), ses_configuration_set=v.get("ses_configuration_set"))


@router.get("", response_model=SmtpOut)
def get_smtp(_: Principal = Depends(require(Permission.SETTINGS_MANAGE)), db: Session = Depends(get_db)) -> SmtpOut:
    row = db.get(AppSetting, KEY)
    if row is None or not row.value:
        return SmtpOut(configured=False)
    v = row.value
    return SmtpOut(configured=True, host=v.get("host"), port=v.get("port"), security=v.get("security"),
                   username=v.get("username"), has_password=bool(v.get("password_enc")),
                   from_address=v["from_address"], from_name=v.get("from_name"), reply_to=v.get("reply_to"),
                   provider=v.get("provider", "smtp"), auth=v.get("auth", "password"),
                   m365_tenant_id=v.get("m365_tenant_id"), m365_client_id=v.get("m365_client_id"),
                   has_m365_client_secret=bool(v.get("m365_client_secret_enc")),
                   m365_cloud=v.get("m365_cloud", "global"), ses_region=v.get("ses_region"),
                   ses_configuration_set=v.get("ses_configuration_set"))


@router.put("", response_model=SmtpOut)
def put_smtp(body: SmtpIn, request: Request, p: Principal = Depends(require(Permission.SETTINGS_MANAGE)),
             db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> SmtpOut:
    smtp = body.provider == "smtp"
    if smtp:
        if body.security == "none" and not settings.smtp_allow_plaintext:
            raise HTTPException(422, "Plaintext SMTP is disabled; use STARTTLS or SSL/TLS")
        try:
            validate_smtp_host(body.host or "", body.port, settings)
        except UnsafeURLError as exc:
            raise HTTPException(422, str(exc)) from exc
    row = db.get(AppSetting, KEY)
    old = dict(row.value) if row and row.value else {}
    box = get_secret_box()
    pw_enc = old.get("password_enc")
    if body.clear_password:
        pw_enc = None
    elif body.password:
        pw_enc = box.encrypt(body.password)
    secret_enc = old.get("m365_client_secret_enc")
    if body.m365_client_secret:
        secret_enc = box.encrypt(body.m365_client_secret)
    oauth = smtp and body.auth == "oauth2_m365"
    if oauth and not secret_enc:
        raise HTTPException(422, "Microsoft 365 OAuth2 needs the client secret")
    value = {"provider": body.provider, "auth": body.auth if smtp else "password",
             "host": body.host.lower() if smtp and body.host else None, "port": body.port if smtp else None,
             "security": body.security if smtp else None, "username": body.username if smtp else None,
             "password_enc": pw_enc if smtp and not oauth else None,
             "m365_tenant_id": body.m365_tenant_id if oauth else None,
             "m365_client_id": body.m365_client_id if oauth else None,
             "m365_client_secret_enc": secret_enc if oauth else None,
             "m365_cloud": body.m365_cloud if oauth else "global",
             "ses_region": body.ses_region if not smtp else None,
             "ses_configuration_set": body.ses_configuration_set if not smtp else None,
             "from_address": str(body.from_address), "from_name": body.from_name,
             "reply_to": str(body.reply_to) if body.reply_to else None}
    if row is None:
        db.add(AppSetting(key=KEY, value=value, updated_by=p.user.username))
    else:
        row.value, row.updated_by = value, p.user.username
    audit.record(db, "settings.smtp_updated", actor=p.user, request=request, target_type="settings", target_id=KEY,
                 details={**{k: v for k, v in value.items() if not k.endswith("_enc")},
                          "password_changed": bool(body.password),
                          "client_secret_changed": bool(body.m365_client_secret)})
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
        message_id = send(msg, [str(body.to)], cfg, settings)
    except Exception as exc:  # noqa: BLE001 - report a sanitized reason to the admin
        audit.record(db, "settings.smtp_test", actor=p.user, request=request, outcome="failure",
                     details={"to": str(body.to), "error": type(exc).__name__})
        db.commit()
        raise HTTPException(502, f"SMTP test failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    audit.record(db, "settings.smtp_test", actor=p.user, request=request,
                 details={"to": str(body.to), "provider": cfg.provider, "auth": cfg.auth})
    db.commit()
    return {"sent": True, "message_id": message_id}


@router.get("/presets")
def presets(_: Principal = Depends(require(Permission.SETTINGS_MANAGE))) -> list[dict]:
    """Starting points for the form (the admin still reviews and saves)."""
    return [
        {"id": "m365_oauth", "label": "Microsoft 365 (OAuth2)", "provider": "smtp", "auth": "oauth2_m365",
         "host": M365_SMTP_HOST["global"], "port": 587, "security": "starttls"},
        {"id": "m365_gov", "label": "Microsoft 365 GCC High (OAuth2)", "provider": "smtp", "auth": "oauth2_m365",
         "host": M365_SMTP_HOST["usgov"], "port": 587, "security": "starttls", "m365_cloud": "usgov"},
        {"id": "ses_api", "label": "Amazon SES (API, IAM role)", "provider": "ses_api"},
        {"id": "ses_smtp", "label": "Amazon SES (SMTP credentials)", "provider": "smtp", "auth": "password",
         "host": "email-smtp.us-east-1.amazonaws.com", "port": 587, "security": "starttls"},
        {"id": "relay", "label": "Corporate relay", "provider": "smtp", "auth": "password", "port": 587,
         "security": "starttls"},
    ]

"""Settings → Certificates & Domain.

Read-only status (active certificate, derived URLs) is available to `settings:manage` in Docker deployments.
Install / CSR / rollback / trusted CA require ``features.ui_tls_management``; ACME additionally ``features.acme``.
Private keys are accepted on upload but never returned or exported. Every change is audited.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst import deployment, tls
from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import AppSetting, TlsCertificate, TlsCsr
from exposurecatalyst.security import certs
from exposurecatalyst.security.rbac import Permission as P

router = APIRouter(prefix="/api/settings/certificates", tags=["settings"])
ADMIN = require(P.SETTINGS_MANAGE)


def managed(settings: Settings = Depends(settings_dep)) -> Settings:
    if not settings.features.ui_tls_management:
        raise HTTPException(403, "Certificate management is disabled (features.ui_tls_management)")
    return settings


async def _read(f: UploadFile | None) -> bytes | None:
    if f is None:
        return None
    data = await f.read(certs.MAX_UPLOAD_BYTES + 1)
    if len(data) > certs.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (1 MB maximum)")
    return data or None


def _cert_out(r: TlsCertificate) -> dict[str, Any]:
    return {"id": r.id, "status": r.status, "source": r.source, "fingerprint": r.fingerprint_sha256,
            "subject": r.subject, "issuer": r.issuer, "serial": r.serial, "sans": r.sans, "key_type": r.key_type,
            "not_before": r.not_before, "not_after": r.not_after, "warnings": r.warnings, "created_by": r.created_by,
            "created_at": r.created_at, "activated_at": r.activated_at}


def _csr_out(r: TlsCsr) -> dict[str, Any]:
    return {"id": r.id, "status": r.status, "common_name": r.common_name, "sans": r.sans, "key_type": r.key_type,
            "created_by": r.created_by, "created_at": r.created_at}


@router.get("")
def status(_: Principal = Depends(ADMIN), db: Session = Depends(get_db),
           settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    history = list(db.scalars(select(TlsCertificate).order_by(TlsCertificate.created_at.desc()).limit(20)))
    pending = list(db.scalars(select(TlsCsr).where(TlsCsr.status == "pending").order_by(TlsCsr.created_at.desc())))
    trusted = db.get(AppSetting, tls.TRUSTED_CA_KEY)
    return {
        "features": settings.features.model_dump(),
        "deployment": settings.deployment,
        "fqdn": settings.fqdn,
        "public_url": settings.public_url,
        "tls_mode": settings.tls_mode,
        "hsts": settings.hsts_enabled,
        "urls": deployment.derived_urls(settings),
        "active": deployment.certificate_status(settings),
        "proxy_available": tls.proxy_available(),
        "history": [_cert_out(r) for r in history],
        "pending_csrs": [_csr_out(r) for r in pending],
        "trusted_ca": (trusted.value.get("subjects") if trusted and trusted.value else []),
        "acme": tls.acme_config(db),
    }


async def _bundle(cert: UploadFile | None, key: UploadFile | None, chain: UploadFile | None,
                  pfx: UploadFile | None, password: str | None, pasted: str | None) -> tuple[certs.Bundle, str]:
    pw = password.encode() if password else None
    pfx_data = await _read(pfx)
    if pfx_data:
        return certs.parse_pkcs12(pfx_data, pw), "pkcs12"
    cert_data, key_data, chain_data = await _read(cert), await _read(key), await _read(chain)
    if pasted and pasted.strip():
        return certs.parse_pem(pasted.encode(), key_data, chain_data, pw), "paste"
    if not cert_data:
        raise certs.CertError("upload a certificate (PEM or bundle), a PKCS#12/PFX file, or paste PEM text")
    return certs.parse_pem(cert_data, key_data, chain_data, pw), "pem"


@router.post("/validate")
async def validate(_: Principal = Depends(ADMIN), settings: Settings = Depends(managed),
                   db: Session = Depends(get_db), cert: UploadFile | None = File(None),
                   key: UploadFile | None = File(None), chain: UploadFile | None = File(None),
                   pfx: UploadFile | None = File(None), password: str | None = Form(None),
                   pasted: str | None = Form(None)) -> dict[str, Any]:
    """Dry run: parse and validate without storing or activating anything."""
    try:
        bundle, source = await _bundle(cert, key, chain, pfx, password, pasted)
    except certs.CertError as exc:
        return {"ok": False, "errors": [str(exc)], "warnings": [], "info": {}}
    report = tls.check(db, settings, bundle)
    return {"ok": report.ok, "errors": report.errors, "warnings": report.warnings, "info": report.info,
            "source": source}


@router.post("/install")
async def install(request: Request, p: Principal = Depends(ADMIN), settings: Settings = Depends(managed),
                  db: Session = Depends(get_db), cert: UploadFile | None = File(None),
                  key: UploadFile | None = File(None), chain: UploadFile | None = File(None),
                  pfx: UploadFile | None = File(None), password: str | None = Form(None),
                  pasted: str | None = Form(None)) -> dict[str, Any]:
    try:
        bundle, source = await _bundle(cert, key, chain, pfx, password, pasted)
        return tls.install(db, settings, bundle, source=source, actor=p.user.username, request=request)
    except certs.CertError as exc:
        raise HTTPException(422, str(exc)) from exc
    except tls.TlsError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post("/rollback")
def rollback(request: Request, p: Principal = Depends(ADMIN), settings: Settings = Depends(managed),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return tls.rollback(db, settings, actor=p.user.username, request=request)
    except tls.TlsError as exc:
        raise HTTPException(409 if "no previous" in str(exc) else 502, str(exc)) from exc


class CsrIn(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    sans: list[str] = Field(default_factory=list, max_length=50)
    key_type: str = "ecdsa-p256"
    organization: str | None = Field(None, max_length=64)
    org_unit: str | None = Field(None, max_length=64)
    locality: str | None = Field(None, max_length=128)
    state: str | None = Field(None, max_length=128)
    country: str | None = Field(None, max_length=2)
    email: EmailStr | None = None


@router.post("/csr", status_code=201)
def create_csr(body: CsrIn, request: Request, p: Principal = Depends(ADMIN), _s: Settings = Depends(managed),
               db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = tls.create_csr(db, common_name=body.common_name.strip().lower(),
                             sans=[s.strip().lower() for s in body.sans if s.strip()], key_type=body.key_type,
                             subject={"organization": body.organization, "org_unit": body.org_unit,
                                      "locality": body.locality, "state": body.state, "country": body.country,
                                      "email": str(body.email) if body.email else None},
                             actor=p.user.username, request=request)
    except certs.CertError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {**_csr_out(row), "csr_pem": row.csr_pem}


def _csr(db: Session, csr_id: int) -> TlsCsr:
    row = db.get(TlsCsr, csr_id)
    if row is None:
        raise HTTPException(404, "CSR not found")
    return row


@router.get("/csr/{csr_id}/download")
def download_csr(csr_id: int, _: Principal = Depends(ADMIN), _s: Settings = Depends(managed),
                 db: Session = Depends(get_db)) -> Response:
    row = _csr(db, csr_id)
    name = "".join(ch if ch.isalnum() or ch in "-." else "_" for ch in row.common_name)
    return Response(row.csr_pem, media_type="application/pkcs10",
                    headers={"Content-Disposition": f'attachment; filename="{name}.csr"'})


@router.post("/csr/{csr_id}/complete")
async def complete_csr(csr_id: int, request: Request, p: Principal = Depends(ADMIN),
                       settings: Settings = Depends(managed), db: Session = Depends(get_db),
                       cert: UploadFile | None = File(None), chain: UploadFile | None = File(None),
                       pasted: str | None = Form(None)) -> dict[str, Any]:
    row = _csr(db, csr_id)
    cert_data = (pasted.encode() if pasted and pasted.strip() else None) or await _read(cert)
    if not cert_data:
        raise HTTPException(422, "upload or paste the signed certificate")
    try:
        return tls.complete_csr(db, settings, row, cert_data, await _read(chain), actor=p.user.username,
                                request=request)
    except certs.CertError as exc:
        raise HTTPException(422, str(exc)) from exc
    except tls.TlsError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.delete("/csr/{csr_id}", status_code=204)
def cancel_csr(csr_id: int, request: Request, p: Principal = Depends(ADMIN), _s: Settings = Depends(managed),
               db: Session = Depends(get_db)) -> None:
    from exposurecatalyst.security import audit

    row = _csr(db, csr_id)
    if row.status == "pending":
        row.status = "cancelled"
        row.key_enc = ""  # the pending private key is destroyed with the request
        audit.record(db, "tls.csr_cancelled", actor=p.user, request=request, target_type="csr", target_id=row.id)
        db.commit()


@router.put("/trusted-ca")
async def put_trusted_ca(request: Request, p: Principal = Depends(ADMIN), settings: Settings = Depends(managed),
                         db: Session = Depends(get_db), bundle: UploadFile | None = File(None),
                         pasted: str | None = Form(None)) -> dict[str, Any]:
    data = (pasted.encode() if pasted and pasted.strip() else None) or await _read(bundle)
    if not data:
        raise HTTPException(422, "upload or paste a PEM CA bundle")
    try:
        return tls.set_trusted_ca(db, settings, data, actor=p.user.username, request=request)
    except certs.CertError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.delete("/trusted-ca")
def delete_trusted_ca(request: Request, p: Principal = Depends(ADMIN), settings: Settings = Depends(managed),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    return tls.set_trusted_ca(db, settings, None, actor=p.user.username, request=request)


class AcmeIn(BaseModel):
    enabled: bool
    email: EmailStr | None = None
    challenge: str = Field("http-01", pattern=r"^(http-01|dns-01)$")
    dns_provider: str | None = Field(None, pattern=r"^(route53|cloudflare)$")
    directory_url: str | None = Field(None, max_length=500)


@router.put("/acme")
def put_acme(body: AcmeIn, request: Request, p: Principal = Depends(ADMIN), settings: Settings = Depends(managed),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    if not settings.features.acme:
        raise HTTPException(403, "ACME is disabled (features.acme)")
    try:
        return tls.set_acme(db, settings, body.model_dump(mode="json"), actor=p.user.username, request=request)
    except tls.TlsError as exc:
        raise HTTPException(422, str(exc)) from exc

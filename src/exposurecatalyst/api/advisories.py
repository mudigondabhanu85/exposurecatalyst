"""Tab 2 — Advisory Email Generator API."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.advisories import excel
from exposurecatalyst.advisories.delivery import build_message, render_pdf, send
from exposurecatalyst.advisories.render import (
    TemplateValidationError,
    build_context,
    logo_data_uri,
    render_html,
    render_subject,
    validate_template,
)
from exposurecatalyst.advisories.service import (
    WorkflowError,
    all_recipients,
    can_approve,
    clean_header,
    exposure,
    new_advisory,
    require_status,
)
from exposurecatalyst.api.deps import Principal, require, require_any, settings_dep
from exposurecatalyst.api.smtp import load_config
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.normalize import CVE_ID_RE
from exposurecatalyst.models import (
    Advisory,
    AdvisoryAsset,
    AdvisoryDelivery,
    AdvisorySourceStatus,
    AdvisoryTemplate,
    AdvisoryTemplateVersion,
    AuditLog,
    Cve,
    DistributionList,
    User,
)
from exposurecatalyst.models.advisory import APPROVED, CANCELLED, DRAFT, IN_REVIEW, SENT, TEMPLATE_RETIRED
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P

router = APIRouter(prefix="/api", tags=["advisories"])
templates_router = APIRouter(prefix="/api", tags=["templates"])
ANY_ADVISORY = require_any(P.ADVISORY_CREATE, P.ADVISORY_APPROVE, P.ADVISORY_SEND, P.ADVISORY_EXPORT)
Emails = list[EmailStr]
DetectionMethod = Literal["vulnerability_check", "software_inventory", "asset_inventory", "manual"]


# ---- schemas --------------------------------------------------------------------------------------

class AssetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = Field(None, max_length=64)
    os: str | None = Field(None, max_length=128)
    cloud_account: str | None = Field(None, max_length=128)
    resource_id: str | None = Field(None, max_length=512)
    owner: str | None = Field(None, max_length=200)
    business_unit: str | None = Field(None, max_length=200)
    environment: str | None = Field(None, max_length=64)
    detection_date: date | None = None
    source_ref: str | None = Field(None, max_length=128)
    support_group: str | None = Field(None, max_length=200)
    asset_class: str | None = Field(None, max_length=100)
    detection_method: DetectionMethod | None = None


class AssetOut(AssetIn):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: int
    is_manual: bool


class MatrixRowOut(BaseModel):
    source: str
    validated: str
    asset_count: int
    last_checked: datetime | None
    manual: bool
    manual_count: int | None
    shown: bool
    check_available: bool | None
    detection_method: str | None
    note: str | None
    finding: str


class AdvisoryOut(BaseModel):
    id: int
    advisory_id: str
    cve_id: str
    status: str
    template_id: int
    template_name: str
    template_version: int
    subject: str
    severity: str
    title: str | None
    summary: str | None
    business_impact: str | None
    remediation: str | None
    workaround: str | None
    affected_products: str | None
    owner_contact: str | None
    sla_due_date: date | None
    vuln_type: str | None
    owner_actions: str | None
    support_actions: str | None
    to_addrs: list[str]
    cc_addrs: list[str]
    bcc_addrs: list[str]
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    review_comment: str | None
    sent_at: datetime | None
    matrix: list[MatrixRowOut]
    total_unique_assets: int
    assets: list[AssetOut]


class AdvisorySummary(BaseModel):
    id: int
    advisory_id: str
    cve_id: str
    status: str
    severity: str
    subject: str
    created_by: str | None
    updated_at: datetime
    sent_at: datetime | None


def _names(db: Session, *ids: int | None) -> dict[int, str]:
    ids_ = [i for i in ids if i]
    return {u.id: u.username for u in db.scalars(select(User).where(User.id.in_(ids_)))} if ids_ else {}


def _out(db: Session, adv: Advisory) -> AdvisoryOut:
    exp = exposure(adv)
    manual = {s.source: s.manual_count for s in adv.sources}
    names = _names(db, adv.created_by, adv.approved_by)
    tv = adv.template_version
    return AdvisoryOut(
        **{k: getattr(adv, k) for k in ("id", "advisory_id", "cve_id", "status", "subject", "severity", "title",
                                        "summary", "business_impact", "remediation", "workaround", "affected_products",
                                        "owner_contact", "sla_due_date", "vuln_type", "owner_actions",
                                        "support_actions", "to_addrs", "cc_addrs", "bcc_addrs",
                                        "created_at", "updated_at", "approved_at", "review_comment", "sent_at")},
        template_id=tv.template_id, template_name=tv.template.name, template_version=tv.version,
        created_by=names.get(adv.created_by), approved_by=names.get(adv.approved_by),
        matrix=[MatrixRowOut(source=r.source, validated=r.validated, asset_count=r.asset_count,
                             last_checked=r.last_checked, manual=r.manual, manual_count=manual.get(r.source),
                             shown=r.shown, check_available=r.check_available, detection_method=r.detection_method,
                             note=r.note, finding=r.finding)
                for r in [*exp.rows, *exp.hidden]],
        total_unique_assets=exp.total_unique,
        assets=[AssetOut.model_validate(a) for a in adv.assets],
    )


def _get(db: Session, advisory_pk: int) -> Advisory:
    adv = db.get(Advisory, advisory_pk)
    if adv is None:
        raise HTTPException(404, "Advisory not found")
    return adv


def _cve(db: Session, cve_id: str) -> Cve | None:
    return db.scalar(select(Cve).where(Cve.cve_id == cve_id))


def _workflow(fn):
    try:
        return fn()
    except WorkflowError as exc:
        raise HTTPException(409, str(exc)) from exc


def _log(db: Session, adv: Advisory, p: Principal, channel: str, *, recipients: dict | None = None,
         message_id: str | None = None, status: str = "ok", error: str | None = None) -> None:
    db.add(AdvisoryDelivery(advisory_pk=adv.id, channel=channel, actor_id=p.user.id, actor_username=p.user.username,
                            recipients=recipients or {}, message_id=message_id, status=status, error=error))


# ---- list / create / read / update ------------------------------------------------------------------

@router.get("/advisories", response_model=list[AdvisorySummary])
def list_advisories(status: str | None = Query(None, pattern="^(draft|in_review|approved|sent|cancelled)$"),
                    cve_id: str | None = Query(None, max_length=32), limit: int = Query(100, ge=1, le=500),
                    _: Principal = Depends(ANY_ADVISORY), db: Session = Depends(get_db)):
    stmt = select(Advisory).order_by(Advisory.updated_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(Advisory.status == status)
    if cve_id:
        stmt = stmt.where(Advisory.cve_id == cve_id.upper())
    rows = list(db.scalars(stmt))
    names = _names(db, *[r.created_by for r in rows])
    return [AdvisorySummary(id=r.id, advisory_id=r.advisory_id, cve_id=r.cve_id, status=r.status, severity=r.severity,
                            subject=r.subject, created_by=names.get(r.created_by), updated_at=r.updated_at,
                            sent_at=r.sent_at) for r in rows]


class CreateIn(BaseModel):
    cve_id: str = Field(max_length=32)
    template_id: int | None = None


@router.post("/advisories", response_model=AdvisoryOut, status_code=201)
def create_advisory(body: CreateIn, request: Request, p: Principal = Depends(require(P.ADVISORY_CREATE)),
                    db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> AdvisoryOut:
    cve_id = body.cve_id.strip().upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(422, "Invalid CVE ID")
    cve = _cve(db, cve_id)
    if cve is None:
        raise HTTPException(404, f"{cve_id} is not in CVE Intelligence yet")
    from exposurecatalyst.connectors.service import integrated_tools

    tools = [*integrated_tools(db), *((s, None) for s in settings.advisory_source_list)]
    adv = _workflow(lambda: new_advisory(db, cve, user_id=p.user.id, sources=tools, template_id=body.template_id))
    adv.subject = render_subject(adv.template_version.subject_template, build_context(adv, cve))
    audit.record(db, "advisory.created", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={"cve_id": cve_id})
    db.commit()
    return _out(db, adv)


@router.get("/advisories/{advisory_pk}", response_model=AdvisoryOut)
def get_advisory(advisory_pk: int, _: Principal = Depends(ANY_ADVISORY), db: Session = Depends(get_db)):
    return _out(db, _get(db, advisory_pk))


class UpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str | None = Field(None, min_length=5, max_length=300)
    title: str | None = Field(None, max_length=512)
    summary: str | None = Field(None, max_length=20_000)
    business_impact: str | None = Field(None, max_length=20_000)
    remediation: str | None = Field(None, max_length=20_000)
    workaround: str | None = Field(None, max_length=20_000)
    affected_products: str | None = Field(None, max_length=5_000)
    owner_contact: str | None = Field(None, max_length=300)
    sla_due_date: date | None = None
    vuln_type: str | None = Field(None, max_length=300)
    owner_actions: str | None = Field(None, max_length=10_000)
    support_actions: str | None = Field(None, max_length=10_000)
    to_addrs: Emails | None = Field(None, max_length=200)
    cc_addrs: Emails | None = Field(None, max_length=200)
    bcc_addrs: Emails | None = Field(None, max_length=200)
    template_id: int | None = None


@router.patch("/advisories/{advisory_pk}", response_model=AdvisoryOut)
def update_advisory(advisory_pk: int, body: UpdateIn, p: Principal = Depends(require(P.ADVISORY_CREATE)),
                    db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    data = body.model_dump(exclude_unset=True)
    if "template_id" in data:
        from exposurecatalyst.advisories.service import pick_template

        tv = _workflow(lambda: pick_template(db, adv.severity, data.pop("template_id")))
        adv.template_version_id, adv.template_version = tv.id, tv
    for k in ("to_addrs", "cc_addrs", "bcc_addrs"):
        if k in data:
            data[k] = list(dict.fromkeys(str(e).lower() for e in data[k]))
    if "subject" in data:
        data["subject"] = clean_header(data["subject"])
    for k, v in data.items():
        setattr(adv, k, v)
    db.commit()
    return _out(db, adv)


@router.post("/advisories/{advisory_pk}/subject/regenerate", response_model=AdvisoryOut)
def regenerate_subject(advisory_pk: int, p: Principal = Depends(require(P.ADVISORY_CREATE)),
                       db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    adv.subject = render_subject(adv.template_version.subject_template, build_context(adv, _cve(db, adv.cve_id)))
    db.commit()
    return _out(db, adv)


# ---- assets & matrix ----------------------------------------------------------------------------------

@router.post("/advisories/{advisory_pk}/assets", response_model=AdvisoryOut, status_code=201)
def add_asset(advisory_pk: int, body: AssetIn, request: Request, p: Principal = Depends(require(P.ADVISORY_CREATE)),
              db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    if not (body.hostname or body.ip_address or body.resource_id):
        raise HTTPException(422, "Provide a hostname, IP address or resource ID")
    adv.assets.append(AdvisoryAsset(**body.model_dump(), is_manual=True))
    audit.record(db, "advisory.asset_added", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={"source": body.source, "manual": True})
    db.commit()
    return _out(db, adv)


@router.put("/advisories/{advisory_pk}/assets/{asset_id}", response_model=AdvisoryOut)
def edit_asset(advisory_pk: int, asset_id: int, body: AssetIn, p: Principal = Depends(require(P.ADVISORY_CREATE)),
               db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    asset = next((a for a in adv.assets if a.id == asset_id), None)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    for k, v in body.model_dump().items():
        setattr(asset, k, v)
    asset.is_manual = True  # any analyst edit makes the row a manual entry
    db.commit()
    return _out(db, adv)


@router.delete("/advisories/{advisory_pk}/assets/{asset_id}", response_model=AdvisoryOut)
def delete_asset(advisory_pk: int, asset_id: int, p: Principal = Depends(require(P.ADVISORY_CREATE)),
                 db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    asset = next((a for a in adv.assets if a.id == asset_id), None)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    adv.assets.remove(asset)
    db.commit()
    return _out(db, adv)


@router.post("/advisories/{advisory_pk}/assets/upload")
async def upload_assets(advisory_pk: int, request: Request, file: UploadFile = File(...),
                        default_source: str = Form("Manual upload", max_length=64),
                        p: Principal = Depends(require(P.ADVISORY_CREATE)), db: Session = Depends(get_db),
                        settings: Settings = Depends(settings_dep)) -> dict:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    data = await file.read(settings.upload_max_bytes + 1)
    if len(data) > settings.upload_max_bytes:
        raise HTTPException(413, f"File larger than {settings.upload_max_bytes // 1_048_576} MB")
    try:
        rows, errors = excel.parse_assets(file.filename or "", data, default_source=default_source.strip() or "Manual",
                                          max_rows=settings.upload_max_rows)
    except excel.ImportError_ as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - malformed workbook
        raise HTTPException(422, "Could not read the file — is it a valid CSV or XLSX?") from exc
    for r in rows:
        adv.assets.append(AdvisoryAsset(**r, is_manual=True))
    audit.record(db, "advisory.assets_uploaded", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={"file": (file.filename or "")[:100], "rows": len(rows)})
    db.commit()
    return {"imported": len(rows), "errors": errors[:50], "advisory": _out(db, adv).model_dump(mode="json")}


class SourceIn(BaseModel):
    """Per-tool settings; only the fields sent are changed."""

    model_config = ConfigDict(extra="forbid")
    manual_count: int | None = Field(None, ge=0, le=1_000_000)
    shown: bool | None = None
    check_available: bool | None = None
    detection_method: DetectionMethod | None = None
    note: str | None = Field(None, max_length=2_000)


@router.put("/advisories/{advisory_pk}/sources/{source}", response_model=AdvisoryOut)
def set_source(advisory_pk: int, source: str, body: SourceIn, request: Request,
               p: Principal = Depends(require(P.ADVISORY_CREATE)), db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    source = clean_header(source, 64)
    if not source:
        raise HTTPException(422, "Source name required")
    data = body.model_dump(exclude_unset=True)
    if data.get("shown") is None:
        data.pop("shown", None)  # visibility is a yes/no choice
    st = next((s for s in adv.sources if s.source == source), None)
    if st is None:
        st = AdvisorySourceStatus(source=source, integrated=False, shown=True)
        adv.sources.append(st)
    if "manual_count" in data:
        st.last_checked = utcnow() if data["manual_count"] is not None else None
    if "note" in data:
        data["note"] = (data["note"] or "").strip() or None
    for k, v in data.items():
        setattr(st, k, v)
    if "shown" in data:
        audit.record(db, "advisory.source_shown" if data["shown"] else "advisory.source_hidden", actor=p.user,
                     request=request, target_type="advisory", target_id=adv.advisory_id, details={"source": source})
    db.commit()
    return _out(db, adv)


@router.get("/advisory-sources")
def advisory_sources(_: Principal = Depends(ANY_ADVISORY), db: Session = Depends(get_db),
                     settings: Settings = Depends(settings_dep)) -> dict:
    """Tools an analyst can add to an advisory: enabled integrations first, then every catalog tool."""
    from exposurecatalyst.advisories.service import DETECTION_METHODS
    from exposurecatalyst.connectors.base import REGISTRY
    from exposurecatalyst.connectors.service import integrated_tools

    integrated = [name for name, _ in integrated_tools(db)]
    catalog = sorted({c.spec.label for c in REGISTRY.values() if "assets_for_cve" in c.spec.capabilities}
                     | set(settings.advisory_source_list))
    return {"integrated": integrated, "catalog": catalog, "detection_methods": DETECTION_METHODS}


# ---- workflow ---------------------------------------------------------------------------------------

@router.post("/advisories/{advisory_pk}/submit", response_model=AdvisoryOut)
def submit(advisory_pk: int, request: Request, p: Principal = Depends(require(P.ADVISORY_CREATE)),
           db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT))
    if not adv.to_addrs:
        raise HTTPException(422, "Add at least one To recipient before submitting for review")
    adv.status, adv.submitted_at, adv.review_comment = IN_REVIEW, utcnow(), None
    audit.record(db, "advisory.submitted", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id)
    db.commit()
    return _out(db, adv)


class ReviewIn(BaseModel):
    comment: str | None = Field(None, max_length=2000)


@router.post("/advisories/{advisory_pk}/approve", response_model=AdvisoryOut)
def approve(advisory_pk: int, body: ReviewIn, request: Request, p: Principal = Depends(require(P.ADVISORY_APPROVE)),
            db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: can_approve(adv, p.user.id))
    adv.status, adv.approved_by, adv.approved_at, adv.review_comment = APPROVED, p.user.id, utcnow(), body.comment
    audit.record(db, "advisory.approved", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={"comment": body.comment})
    db.commit()
    return _out(db, adv)


@router.post("/advisories/{advisory_pk}/reject", response_model=AdvisoryOut)
def reject(advisory_pk: int, body: ReviewIn, request: Request, p: Principal = Depends(require(P.ADVISORY_APPROVE)),
           db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, IN_REVIEW))
    if not body.comment:
        raise HTTPException(422, "Explain what needs to change")
    adv.status, adv.review_comment = DRAFT, body.comment
    audit.record(db, "advisory.rejected", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={"comment": body.comment})
    db.commit()
    return _out(db, adv)


@router.post("/advisories/{advisory_pk}/cancel", response_model=AdvisoryOut)
def cancel(advisory_pk: int, request: Request, p: Principal = Depends(require(P.ADVISORY_CREATE)),
           db: Session = Depends(get_db)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, DRAFT, IN_REVIEW, APPROVED))
    adv.status = CANCELLED
    audit.record(db, "advisory.cancelled", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id)
    db.commit()
    return _out(db, adv)


class SendIn(BaseModel):
    confirm: bool


@router.post("/advisories/{advisory_pk}/send", response_model=AdvisoryOut)
def send_advisory(advisory_pk: int, body: SendIn, request: Request, p: Principal = Depends(require(P.ADVISORY_SEND)),
                  db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> AdvisoryOut:
    adv = _get(db, advisory_pk)
    _workflow(lambda: require_status(adv, APPROVED))
    if not body.confirm:
        raise HTTPException(422, "Sending requires explicit confirmation")
    cfg = load_config(db)
    if cfg is None:
        raise HTTPException(409, "SMTP is not configured — an admin can set it up in Settings → SMTP")
    cve = _cve(db, adv.cve_id)
    msg = build_message(adv, cve, from_addr=cfg.from_address, from_name=cfg.from_name, reply_to=cfg.reply_to,
                        xlsx=excel.build_workbook(adv, cve), xlsx_name=excel.workbook_name(adv), draft=False)
    recipients = {"to": adv.to_addrs, "cc": adv.cc_addrs, "bcc": adv.bcc_addrs}
    try:
        message_id = send(msg, all_recipients(adv), cfg, settings)
    except Exception as exc:  # noqa: BLE001 - surfaced to user + audited, never a stack trace
        reason = f"{type(exc).__name__}: {str(exc)[:200]}"
        _log(db, adv, p, "smtp", recipients=recipients, status="error", error=reason)
        audit.record(db, "advisory.send_failed", actor=p.user, request=request, target_type="advisory",
                     target_id=adv.advisory_id, outcome="failure", details={"error": reason})
        db.commit()
        raise HTTPException(502, f"SMTP delivery failed: {reason}") from exc
    adv.status, adv.sent_at, adv.sent_by = SENT, utcnow(), p.user.id
    _log(db, adv, p, "smtp", recipients=recipients, message_id=message_id)
    audit.record(db, "advisory.sent", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={**recipients, "subject": adv.subject, "message_id": message_id})
    db.commit()
    return _out(db, adv)


# ---- preview & exports ------------------------------------------------------------------------------

@router.get("/advisories/{advisory_pk}/preview", response_class=HTMLResponse)
def preview(advisory_pk: int, _: Principal = Depends(ANY_ADVISORY), db: Session = Depends(get_db)) -> HTMLResponse:
    adv = _get(db, advisory_pk)
    mark = None if adv.status in (APPROVED, SENT) else f"PREVIEW — {adv.status.replace('_', ' ').upper()}, NOT APPROVED"
    return HTMLResponse(render_html(adv, _cve(db, adv.cve_id), logo_src=logo_data_uri(), watermark=mark))


Fmt = Literal["eml", "html", "pdf", "xlsx", "clipboard"]


@router.get("/advisories/{advisory_pk}/export/{fmt}")
def export(advisory_pk: int, fmt: Fmt, request: Request, p: Principal = Depends(require(P.ADVISORY_EXPORT)),
           db: Session = Depends(get_db)) -> Response:
    adv = _get(db, advisory_pk)
    # Exports leave the platform: only reviewed content may leave (prevents bypassing approval via .eml).
    _workflow(lambda: require_status(adv, APPROVED, SENT))
    cve = _cve(db, adv.cve_id)
    base = f"{adv.advisory_id}_{adv.cve_id}"
    if fmt == "eml":
        cfg = load_config(db)
        from_addr = cfg.from_address if cfg else "advisories@exposurecatalyst.invalid"
        msg = build_message(adv, cve, from_addr=from_addr, from_name=cfg.from_name if cfg else None,
                            reply_to=cfg.reply_to if cfg else None, xlsx=excel.build_workbook(adv, cve),
                            xlsx_name=excel.workbook_name(adv), draft=True)
        resp: Response = Response(msg.as_bytes(), media_type="message/rfc822",
                                  headers={"Content-Disposition": f'attachment; filename="{base}.eml"'})
    elif fmt in ("html", "clipboard"):
        html = render_html(adv, cve, logo_src=logo_data_uri())
        headers = {} if fmt == "clipboard" else {"Content-Disposition": f'attachment; filename="{base}.html"'}
        # text/plain for the clipboard fetch so it is never rendered as a page; the SPA writes it as text/html.
        resp = (PlainTextResponse(html) if fmt == "clipboard" else Response(html, media_type="text/html",
                                                                             headers=headers))
    elif fmt == "pdf":
        resp = Response(render_pdf(render_html(adv, cve, logo_src=logo_data_uri())), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{base}.pdf"'})
    else:
        resp = Response(excel.build_workbook(adv, cve),
                        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": f'attachment; filename="{excel.workbook_name(adv)}"'})
    _log(db, adv, p, fmt)
    audit.record(db, "advisory.exported", actor=p.user, request=request, target_type="advisory",
                 target_id=adv.advisory_id, details={"format": fmt})
    db.commit()
    return resp


class HistoryItem(BaseModel):
    at: datetime
    actor: str | None
    action: str
    details: dict


@router.get("/advisories/{advisory_pk}/history", response_model=list[HistoryItem])
def history(advisory_pk: int, _: Principal = Depends(ANY_ADVISORY), db: Session = Depends(get_db)):
    adv = _get(db, advisory_pk)
    rows = db.scalars(select(AuditLog).where(AuditLog.target_type == "advisory",
                                             AuditLog.target_id == adv.advisory_id).order_by(AuditLog.id))
    return [HistoryItem(at=r.occurred_at, actor=r.actor_username, action=r.action, details=r.details) for r in rows]


# ---- distribution lists -----------------------------------------------------------------------------

class DistListIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(None, max_length=300)
    to_addrs: Emails = Field(default_factory=list, max_length=200)
    cc_addrs: Emails = Field(default_factory=list, max_length=200)
    bcc_addrs: Emails = Field(default_factory=list, max_length=200)


class DistListOut(DistListIn):
    id: int


@router.get("/distribution-lists", response_model=list[DistListOut])
def list_dist(_: Principal = Depends(ANY_ADVISORY), db: Session = Depends(get_db)):
    rows = db.scalars(select(DistributionList).order_by(DistributionList.name))
    return [DistListOut(id=d.id, name=d.name, description=d.description, to_addrs=d.to_addrs, cc_addrs=d.cc_addrs,
                        bcc_addrs=d.bcc_addrs) for d in rows]


@router.post("/distribution-lists", response_model=DistListOut, status_code=201)
def create_dist(body: DistListIn, request: Request, p: Principal = Depends(require(P.ADVISORY_CREATE)),
                db: Session = Depends(get_db)) -> DistListOut:
    if db.scalar(select(DistributionList).where(func.lower(DistributionList.name) == body.name.strip().lower())):
        raise HTTPException(409, "A distribution list with that name exists")
    addrs = {k: [str(e).lower() for e in getattr(body, k)] for k in ("to_addrs", "cc_addrs", "bcc_addrs")}
    d = DistributionList(name=body.name.strip(), description=body.description, created_by=p.user.id, **addrs)
    db.add(d)
    db.flush()
    audit.record(db, "distribution_list.created", actor=p.user, request=request, target_type="distribution_list",
                 target_id=d.id, details={"name": d.name})
    db.commit()
    return DistListOut(id=d.id, name=d.name, description=d.description, to_addrs=d.to_addrs, cc_addrs=d.cc_addrs,
                       bcc_addrs=d.bcc_addrs)


@router.delete("/distribution-lists/{list_id}", status_code=204)
def delete_dist(list_id: int, request: Request, p: Principal = Depends(require(P.ADVISORY_CREATE)),
                db: Session = Depends(get_db)) -> Response:
    d = db.get(DistributionList, list_id)
    if d is None:
        raise HTTPException(404, "Not found")
    audit.record(db, "distribution_list.deleted", actor=p.user, request=request, target_type="distribution_list",
                 target_id=d.id, details={"name": d.name})
    db.delete(d)
    db.commit()
    return Response(status_code=204)


# ---- templates (versioned: draft → in_review → approved) ---------------------------------------------

class VersionOut(BaseModel):
    id: int
    version: int
    status: str
    subject_template: str
    body_template: str
    change_note: str | None
    created_by: str | None
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None


class TemplateOut(BaseModel):
    id: int
    name: str
    kind: str
    description: str | None
    is_system: bool
    versions: list[VersionOut]


def _tpl_out(db: Session, t: AdvisoryTemplate) -> TemplateOut:
    names = _names(db, *[v.created_by for v in t.versions], *[v.approved_by for v in t.versions])
    return TemplateOut(id=t.id, name=t.name, kind=t.kind, description=t.description, is_system=t.is_system,
                       versions=[VersionOut(id=v.id, version=v.version, status=v.status,
                                            subject_template=v.subject_template, body_template=v.body_template,
                                            change_note=v.change_note, created_by=names.get(v.created_by) or (
                                                "system" if t.is_system and v.version == 1 else None),
                                            created_at=v.created_at, approved_by=names.get(v.approved_by),
                                            approved_at=v.approved_at) for v in t.versions])


@templates_router.get("/templates", response_model=list[TemplateOut])
def list_templates(_: Principal = Depends(require_any(P.ADVISORY_CREATE, P.ADVISORY_APPROVE, P.TEMPLATE_MANAGE)),
                   db: Session = Depends(get_db)):
    return [_tpl_out(db, t) for t in db.scalars(select(AdvisoryTemplate).order_by(AdvisoryTemplate.id))]


class VersionIn(BaseModel):
    subject_template: str = Field(min_length=5, max_length=500)
    body_template: str = Field(min_length=10, max_length=50_000)
    change_note: str | None = Field(None, max_length=500)


@templates_router.post("/templates/{template_id}/versions", response_model=TemplateOut, status_code=201)
def create_version(template_id: int, body: VersionIn, request: Request,
                   p: Principal = Depends(require(P.TEMPLATE_MANAGE)), db: Session = Depends(get_db)) -> TemplateOut:
    t = db.get(AdvisoryTemplate, template_id)
    if t is None:
        raise HTTPException(404, "Template not found")
    try:
        validate_template(body.subject_template, body.body_template)
    except TemplateValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    nxt = max((v.version for v in t.versions), default=0) + 1
    t.versions.append(AdvisoryTemplateVersion(version=nxt, status=DRAFT, subject_template=body.subject_template,
                                              body_template=body.body_template, change_note=body.change_note,
                                              created_by=p.user.id))
    audit.record(db, "template.version_created", actor=p.user, request=request, target_type="template",
                 target_id=f"{t.name} v{nxt}")
    db.commit()
    return _tpl_out(db, t)


def _version(db: Session, version_id: int) -> AdvisoryTemplateVersion:
    v = db.get(AdvisoryTemplateVersion, version_id)
    if v is None:
        raise HTTPException(404, "Template version not found")
    return v


@templates_router.post("/template-versions/{version_id}/submit", response_model=TemplateOut)
def submit_version(version_id: int, request: Request, p: Principal = Depends(require(P.TEMPLATE_MANAGE)),
                   db: Session = Depends(get_db)) -> TemplateOut:
    v = _version(db, version_id)
    if v.status != DRAFT:
        raise HTTPException(409, f"version is '{v.status}'")
    v.status, v.submitted_at = IN_REVIEW, utcnow()
    audit.record(db, "template.version_submitted", actor=p.user, request=request, target_type="template",
                 target_id=f"{v.template.name} v{v.version}")
    db.commit()
    return _tpl_out(db, v.template)


@templates_router.post("/template-versions/{version_id}/approve", response_model=TemplateOut)
def approve_version(version_id: int, request: Request, p: Principal = Depends(require(P.ADVISORY_APPROVE)),
                    db: Session = Depends(get_db)) -> TemplateOut:
    v = _version(db, version_id)
    if v.status != IN_REVIEW:
        raise HTTPException(409, f"version is '{v.status}'")
    if v.created_by == p.user.id:
        raise HTTPException(409, "segregation of duties: you cannot approve a template version you authored")
    for other in v.template.versions:
        if other.status == APPROVED:
            other.status = TEMPLATE_RETIRED  # previous approved version stays for advisories that used it
    v.status, v.approved_by, v.approved_at = APPROVED, p.user.id, utcnow()
    audit.record(db, "template.version_approved", actor=p.user, request=request, target_type="template",
                 target_id=f"{v.template.name} v{v.version}")
    db.commit()
    return _tpl_out(db, v.template)

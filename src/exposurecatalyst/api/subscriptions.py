"""Integrations → Threat Intel & News Subscriptions (features.subscriptions; 403 when off).

Configuration: integration:manage. Viewing intel: cve:view / news:view (TLP:RED only with intel:manage).
Manual entry, attachments and import: intel:manage. Credentials are write-only; every change is audited.
"""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, current_principal, require, require_any, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import IntelAttachment, IntelItem, IntelSubscription
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P
from exposurecatalyst.subscriptions import engine, jsonpath
from exposurecatalyst.subscriptions import service as svc
from exposurecatalyst.subscriptions.presets import AUTH_TYPES, PRESETS, SECRET_KEYS, catalog
from exposurecatalyst.subscriptions.service import EMAIL_MODES, LICENSE_FIELDS

router = APIRouter(prefix="/api/subscriptions", tags=["subscriptions"])
MAX_ATTACHMENT = 10_000_000
ATTACHMENT_TYPES = {"application/pdf": b"%PDF-", "text/html": None}
PAGINATION = ("none", "offset", "page", "cursor", "next_url", "link_header")


def enabled(settings: Settings = Depends(settings_dep)) -> Settings:
    if not settings.features.subscriptions:
        raise HTTPException(403, "Subscriptions are disabled (features.subscriptions)")
    return settings


MANAGE = require(P.INTEGRATION_MANAGE)
INTEL = require(P.INTEL_MANAGE)
VIEW = require_any(P.CVE_VIEW, P.NEWS_VIEW)


# ---- schemas -----------------------------------------------------------------------------------------------


class SubIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    preset: str
    vendor: str | None = Field(None, max_length=100)
    base_url: str | None = Field(None, max_length=500)
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    license: dict[str, Any] = Field(default_factory=dict)
    redistribution: dict[str, Any] = Field(default_factory=dict)

    @field_validator("preset")
    @classmethod
    def known(cls, v: str) -> str:
        if v not in PRESETS:
            raise ValueError(f"unknown preset '{v}'")
        return v


class SubPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=100)
    base_url: str | None = Field(None, max_length=500)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = Field(None, description="Only keys present change; empty string clears")
    license: dict[str, Any] | None = None
    redistribution: dict[str, Any] | None = None


def _clean_config(cfg: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in cfg.items():
        if k == "auth":
            if not isinstance(v, dict) or v.get("type") not in AUTH_TYPES:
                raise HTTPException(422, f"auth.type must be one of {', '.join(AUTH_TYPES)}")
            for url_key in ("token_url",):
                if v.get(url_key) and not str(v[url_key]).startswith("https://"):
                    raise HTTPException(422, "auth.token_url must be https")
            out[k] = {
                kk: str(vv)[:500]
                for kk, vv in v.items()
                if kk in ("type", "header", "prefix", "param", "token_url", "scope", "client_auth", "grant_type")
            }
        elif k == "headers":
            if not isinstance(v, dict):
                raise HTTPException(422, "headers must be an object")
            out[k] = {str(hk)[:100]: str(hv)[:500] for hk, hv in v.items()}
        elif k == "endpoints":
            if not isinstance(v, list) or len(v) > 10:
                raise HTTPException(422, "endpoints must be a list (maximum 10)")
            out[k] = [_clean_endpoint(e) for e in v]
        elif k in ("poll_minutes", "rate_per_minute", "page_size", "initial_days"):
            try:
                n = int(v)
            except (TypeError, ValueError) as exc:
                raise HTTPException(422, f"{k} must be a number") from exc
            limits = {
                "poll_minutes": (5, 10080),
                "rate_per_minute": (1, 600),
                "page_size": (1, 1000),
                "initial_days": (1, 3650),
            }[k]
            if not limits[0] <= n <= limits[1]:
                raise HTTPException(422, f"{k} must be between {limits[0]} and {limits[1]}")
            out[k] = n
        elif k in ("collection_id", "stream_id", "tenant_id", "company_id", "account_id", "list_ids"):
            out[k] = str(v)[:300]
        else:
            raise HTTPException(422, f"unknown setting '{k}'")
    return out


def _clean_endpoint(e: Any) -> dict[str, Any]:
    if not isinstance(e, dict):
        raise HTTPException(422, "each endpoint must be an object")
    if (e.get("method") or "GET").upper() != "GET":
        raise HTTPException(422, "subscriptions are read-only: endpoint method must be GET")
    if e.get("target", "cve") not in ("cve", "news"):
        raise HTTPException(422, "endpoint target must be cve or news")
    path = str(e.get("path") or "")
    if "://" in path or path.startswith("//"):
        raise HTTPException(422, "endpoint path must be relative to the base URL")
    pag = e.get("pagination") or {"type": "none"}
    if pag.get("type") not in PAGINATION:
        raise HTTPException(422, f"pagination.type must be one of {', '.join(PAGINATION)}")
    mapping = e.get("mapping") or {}
    allowed = {
        "external_id",
        "cve_id",
        "title",
        "summary",
        "description",
        "severity",
        "exploited",
        "references",
        "url",
        "published",
        "tags",
    }
    if set(mapping) - allowed:
        raise HTTPException(422, f"unknown mapping field(s): {', '.join(sorted(set(mapping) - allowed))}")
    for f, p in [
        *mapping.items(),
        ("results_path", e.get("results_path") or "$[*]"),
        *([("next_path", pag["next_path"])] if pag.get("next_path") else []),
    ]:
        if isinstance(p, str) and p.startswith("="):
            continue
        try:
            jsonpath.parse(str(p))
        except jsonpath.PathError as exc:
            raise HTTPException(422, f"{f}: {exc}") from exc
    return {
        "name": str(e.get("name") or "Endpoint")[:100],
        "target": e.get("target", "cve"),
        "method": "GET",
        "path": path[:500],
        "params": {str(k)[:100]: str(v)[:500] for k, v in (e.get("params") or {}).items()},
        "results_path": str(e.get("results_path") or "$[*]")[:300],
        "pagination": {k: (v if k in ("drop_params",) else str(v)[:300]) for k, v in pag.items()},
        "mapping": {k: str(v)[:300] for k, v in mapping.items()},
    }


def _clean_license(lic: dict[str, Any]) -> dict[str, Any]:
    unknown = set(lic) - set(LICENSE_FIELDS)
    if unknown:
        raise HTTPException(422, f"unknown licence field(s): {', '.join(sorted(unknown))}")
    out: dict[str, Any] = {}
    for k, v in lic.items():
        if v in (None, ""):
            continue
        if k in ("start_date", "renewal_date"):
            try:
                v = date.fromisoformat(str(v)).isoformat()
            except ValueError as exc:
                raise HTTPException(422, f"{k} must be YYYY-MM-DD") from exc
        elif k in ("seats", "api_quota"):
            try:
                v = int(v)
            except (TypeError, ValueError) as exc:
                raise HTTPException(422, f"{k} must be a number") from exc
        elif k == "quota_period" and v not in ("day", "month", "year"):
            raise HTTPException(422, "quota_period must be day, month or year")
        else:
            v = str(v)[:1000]
        out[k] = v
    return out


def _clean_redistribution(r: dict[str, Any]) -> dict[str, Any]:
    out = {}
    if "email" in r:
        if r["email"] not in EMAIL_MODES:
            raise HTTPException(422, f"email must be one of {', '.join(EMAIL_MODES)}")
        out["email"] = r["email"]
    if "ai" in r:
        out["ai"] = bool(r["ai"])
    if "default_tlp" in r:
        tlp = str(r["default_tlp"]).upper()
        if tlp not in engine.TLP:
            raise HTTPException(422, f"default_tlp must be one of {', '.join(engine.TLP)}")
        out["default_tlp"] = tlp
    return out


def _check_secrets(secrets: dict[str, str]) -> dict[str, str]:
    unknown = set(secrets) - SECRET_KEYS
    if unknown:
        raise HTTPException(422, f"unknown secret(s): {', '.join(sorted(unknown))}")
    return {k: str(v)[:4096] for k, v in secrets.items()}


def _base_url(preset: str, url: str | None, settings: Settings) -> str | None:
    if PRESETS[preset]["source_type"] == "manual":
        return None
    if not url:
        raise HTTPException(422, "base URL is required")
    try:
        return engine.validate_base_url(preset, url, settings)
    except engine.SourceError as exc:
        raise HTTPException(422, f"Base URL rejected: {exc}") from exc


def _out(sub: IntelSubscription, db: Session) -> dict[str, Any]:
    now = svc.utcnow()
    count = db.scalar(select(func.count()).select_from(IntelItem).where(IntelItem.subscription_id == sub.id)) or 0
    preset = PRESETS.get(sub.preset, {})
    return {
        "id": sub.id,
        "name": sub.name,
        "vendor": sub.vendor,
        "preset": sub.preset,
        "source_type": sub.source_type,
        "api_status": preset.get("api_status"),
        "enabled": sub.enabled,
        "base_url": sub.base_url,
        "config": sub.config or {},
        "effective_config": svc.effective_config(sub.preset, sub.config or {}),
        "secrets_set": sorted(k for k, v in svc.load_secrets(sub).items() if v),
        "license": sub.license or {},
        "redistribution": svc.redistribution(sub),
        "status": sub.status,
        "last_sync_at": sub.last_sync_at,
        "last_success_at": sub.last_success_at,
        "last_error": sub.last_error,
        "error_log": sub.error_log or [],
        "usage": svc._usage(sub, now),
        "quota_left": svc.quota_left(sub, now),
        "items": count,
    }


def _get(db: Session, sub_id: int) -> IntelSubscription:
    sub = db.get(IntelSubscription, sub_id)
    if sub is None:
        raise HTTPException(404, "Subscription not found")
    return sub


# ---- configuration -----------------------------------------------------------------------------------------


@router.get("/presets")
def presets(_: Principal = Depends(MANAGE), _s: Settings = Depends(enabled)) -> list[dict[str, Any]]:
    return catalog()


@router.get("/sources")
def source_names(_: Principal = Depends(require_any(P.INTEL_MANAGE, P.INTEGRATION_MANAGE)),
                 _s: Settings = Depends(enabled), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Names only (no configuration) — for choosing the source of manual intel / imports."""
    return [{"id": s.id, "name": s.name, "vendor": s.vendor, "source_type": s.source_type,
             "default_tlp": svc.redistribution(s)["default_tlp"]}
            for s in db.scalars(select(IntelSubscription).order_by(IntelSubscription.name))]


@router.get("")
def list_subscriptions(
    _: Principal = Depends(MANAGE), _s: Settings = Depends(enabled), db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    return [_out(s, db) for s in db.scalars(select(IntelSubscription).order_by(IntelSubscription.name))]


@router.post("", status_code=201)
def create(
    body: SubIn,
    request: Request,
    p: Principal = Depends(MANAGE),
    settings: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if db.scalar(select(IntelSubscription).where(func.lower(IntelSubscription.name) == body.name.strip().lower())):
        raise HTTPException(409, "A subscription with that name exists")
    preset = PRESETS[body.preset]
    sub = IntelSubscription(
        name=body.name.strip(),
        vendor=(body.vendor or preset["vendor"])[:100],
        preset=body.preset,
        source_type=preset["source_type"],
        enabled=body.enabled,
        base_url=_base_url(body.preset, body.base_url or preset.get("base_url"), settings),
        config=_clean_config(body.config),
        license=_clean_license(body.license),
        redistribution=_clean_redistribution(body.redistribution),
        error_log=[],
        usage={},
        state={},
        created_by=p.user.username,
    )
    svc.store_secrets(sub, _check_secrets(body.secrets))
    db.add(sub)
    db.flush()
    audit.record(
        db,
        "subscription.created",
        actor=p.user,
        request=request,
        target_type="subscription",
        target_id=sub.id,
        details={
            "name": sub.name,
            "preset": sub.preset,
            "base_url": sub.base_url,
            "secrets_set": sorted(body.secrets),
            "redistribution": sub.redistribution,
        },
    )
    db.commit()
    return _out(sub, db)


@router.patch("/{sub_id}")
def update(
    sub_id: int,
    body: SubPatch,
    request: Request,
    p: Principal = Depends(MANAGE),
    settings: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    sub = _get(db, sub_id)
    changed: dict[str, Any] = {}
    if body.name is not None:
        sub.name = changed["name"] = body.name.strip()
    if body.base_url is not None:
        sub.base_url = changed["base_url"] = _base_url(sub.preset, body.base_url, settings)
        sub.status = "never"
    if body.config is not None:
        sub.config = changed["config"] = _clean_config({**(sub.config or {}), **body.config})
    if body.secrets is not None:
        merged = {**svc.load_secrets(sub), **_check_secrets(body.secrets)}
        svc.store_secrets(sub, merged)
        changed["secrets_changed"] = sorted(body.secrets)
        sub.status = "never"
    if body.license is not None:
        sub.license = changed["license"] = _clean_license(body.license)
    if body.redistribution is not None:
        sub.redistribution = changed["redistribution"] = _clean_redistribution(
            {**(sub.redistribution or {}), **body.redistribution}
        )
    if body.enabled is not None:
        sub.enabled = changed["enabled"] = body.enabled
    audit.record(
        db,
        "subscription.updated",
        actor=p.user,
        request=request,
        target_type="subscription",
        target_id=sub.id,
        details=changed,
    )
    db.commit()
    return _out(sub, db)


@router.delete("/{sub_id}", status_code=204)
def delete(
    sub_id: int,
    request: Request,
    p: Principal = Depends(MANAGE),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> None:
    sub = _get(db, sub_id)
    audit.record(
        db,
        "subscription.deleted",
        actor=p.user,
        request=request,
        target_type="subscription",
        target_id=sub.id,
        details={"name": sub.name},
    )
    db.delete(sub)
    db.commit()


class PreviewIn(BaseModel):
    subscription_id: int | None = None
    preset: str | None = None
    base_url: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)


@router.post("/preview")
def preview_unsaved(
    body: PreviewIn,
    p: Principal = Depends(MANAGE),
    settings: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Test & preview before saving: first parsed records with the given (unsaved) settings."""
    base = _get(db, body.subscription_id) if body.subscription_id else None
    preset = body.preset or (base.preset if base else None)
    if preset not in PRESETS:
        raise HTTPException(422, "preset is required")
    tmp = IntelSubscription(
        name="preview",
        vendor="",
        preset=preset,
        source_type=PRESETS[preset]["source_type"],
        base_url=_base_url(
            preset, body.base_url or (base.base_url if base else None) or PRESETS[preset].get("base_url"), settings
        ),
        config={**((base.config if base else None) or {}), **_clean_config(body.config)},
        state={},
    )
    secrets = {**(svc.load_secrets(base) if base else {}), **_check_secrets(body.secrets)}
    try:
        return svc.preview(tmp, settings, secrets=secrets)
    except (engine.SourceError, jsonpath.PathError) as exc:
        return {"ok": False, "error": str(exc), "records": []}
    except Exception as exc:  # noqa: BLE001 - surfaced to the admin, sanitized
        return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}", "records": []}


@router.post("/{sub_id}/test")
def test(
    sub_id: int,
    request: Request,
    p: Principal = Depends(MANAGE),
    settings: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    sub = _get(db, sub_id)
    if sub.source_type == "manual":
        return {"ok": True, "records": [], "message": "Manual subscriptions have no connection to test"}
    try:
        res = svc.preview(sub, settings)
        sub.status, sub.last_error = "ok", None
    except Exception as exc:  # noqa: BLE001
        res = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}", "records": []}
        svc._log_error(sub, res["error"], svc.utcnow())
    audit.record(
        db,
        "subscription.tested",
        actor=p.user,
        request=request,
        target_type="subscription",
        target_id=sub.id,
        outcome="success" if res["ok"] else "failure",
        details={"error": res.get("error")},
    )
    db.commit()
    return res


@router.post("/{sub_id}/sync")
def sync_now(
    sub_id: int,
    request: Request,
    p: Principal = Depends(MANAGE),
    settings: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    sub = _get(db, sub_id)
    if sub.source_type == "manual":
        raise HTTPException(409, "Manual subscriptions are not pulled")
    res = svc.sync(db, sub, settings)
    audit.record(
        db,
        "subscription.synced",
        actor=p.user,
        request=request,
        target_type="subscription",
        target_id=sub.id,
        outcome="success" if res["ok"] else "failure",
        details=res,
    )
    db.commit()
    return res


# ---- intel items -------------------------------------------------------------------------------------------


def _item_out(i: IntelItem, *, full: bool = True) -> dict[str, Any]:
    return {
        "id": i.id,
        "subscription_id": i.subscription_id,
        "source": svc.attribution(i),
        "vendor": i.subscription.vendor,
        "kind": i.kind,
        "title": i.title,
        "cve_ids": i.cve_ids,
        "summary": i.summary,
        "description": i.description if full else None,
        "severity": i.severity,
        "exploited": i.exploited,
        "references": i.references,
        "url": i.url,
        "published_at": i.published_at,
        "tags": i.tags,
        "tlp": i.tlp,
        "analyst_notes": i.analyst_notes if full else None,
        "is_manual": i.is_manual,
        "attachments": [
            {"id": a.id, "filename": a.filename, "size": a.size, "content_type": a.content_type} for a in i.attachments
        ],
        "created_by": i.created_by,
        "created_at": i.created_at,
    }


@router.get("/intel")
def intel(
    cve_id: str | None = None,
    kind: str | None = None,
    limit: int = 100,
    p: Principal = Depends(VIEW),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    if kind not in (None, "cve", "news", "advisory"):
        raise HTTPException(422, "kind must be cve, news or advisory")
    if cve_id is not None and not engine.CVE_RE.fullmatch(cve_id.upper()):
        raise HTTPException(422, "Invalid CVE ID")
    can_red = str(P.INTEL_MANAGE) in p.permissions
    rows = svc.visible_items(
        db, cve_id=cve_id.upper() if cve_id else None, kind=kind, can_red=can_red, limit=max(1, min(limit, 500))
    )
    return [_item_out(r) for r in rows]


class ItemIn(BaseModel):
    subscription_id: int
    kind: str = "cve"
    title: str | None = Field(None, max_length=500)
    cve_ids: list[str] = Field(default_factory=list, max_length=50)
    summary: str | None = Field(None, max_length=5000)
    description: str | None = Field(None, max_length=50000)
    severity: str | None = None
    exploited: bool | None = None
    url: str | None = Field(None, max_length=1000)
    references: list[str] = Field(default_factory=list, max_length=20)
    published_at: str | None = None
    tags: list[str] = Field(default_factory=list, max_length=20)
    tlp: str | None = None
    analyst_notes: str | None = Field(None, max_length=20000)


@router.post("/intel", status_code=201)
def create_item(
    body: ItemIn,
    request: Request,
    p: Principal = Depends(INTEL),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    sub = _get(db, body.subscription_id)
    try:
        data = svc.normalize_manual(
            body.model_dump(exclude={"subscription_id"}), default_tlp=svc.redistribution(sub)["default_tlp"]
        )
    except svc.IntelError as exc:
        raise HTTPException(422, str(exc)) from exc
    item = svc.create_manual(db, sub, data, actor=p.user.username)
    db.flush()
    audit.record(
        db,
        "intel.created",
        actor=p.user,
        request=request,
        target_type="intel",
        target_id=item.id,
        details={"subscription": sub.name, "kind": item.kind, "cve_ids": item.cve_ids, "tlp": item.tlp},
    )
    db.commit()
    db.refresh(item)
    return _item_out(item)


def _manual_item(db: Session, item_id: int) -> IntelItem:
    item = db.get(IntelItem, item_id)
    if item is None:
        raise HTTPException(404, "Intel item not found")
    if not item.is_manual:
        raise HTTPException(409, "Only manual items can be changed (pulled items are owned by the source)")
    return item


@router.patch("/intel/{item_id}")
def update_item(
    item_id: int,
    body: ItemIn,
    request: Request,
    p: Principal = Depends(INTEL),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = _manual_item(db, item_id)
    try:
        data = svc.normalize_manual(body.model_dump(exclude={"subscription_id"}), default_tlp=item.tlp)
    except svc.IntelError as exc:
        raise HTTPException(422, str(exc)) from exc
    for k, v in data.items():
        setattr(item, k, v)
    audit.record(
        db,
        "intel.updated",
        actor=p.user,
        request=request,
        target_type="intel",
        target_id=item.id,
        details={"tlp": item.tlp, "cve_ids": item.cve_ids},
    )
    db.commit()
    db.refresh(item)
    return _item_out(item)


@router.delete("/intel/{item_id}", status_code=204)
def delete_item(
    item_id: int,
    request: Request,
    p: Principal = Depends(INTEL),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> None:
    item = _manual_item(db, item_id)
    audit.record(
        db,
        "intel.deleted",
        actor=p.user,
        request=request,
        target_type="intel",
        target_id=item.id,
        details={"title": item.title},
    )
    db.delete(item)
    db.commit()


@router.post("/intel/{item_id}/attachments", status_code=201)
async def add_attachment(
    item_id: int,
    request: Request,
    file: UploadFile = File(...),
    p: Principal = Depends(INTEL),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    item = _manual_item(db, item_id)
    data = await file.read(MAX_ATTACHMENT + 1)
    if len(data) > MAX_ATTACHMENT:
        raise HTTPException(413, "attachment too large (10 MB maximum)")
    name = (file.filename or "attachment").replace("/", "_").replace("\\", "_")[:255]
    if data.startswith(b"%PDF-"):
        ctype = "application/pdf"
    elif name.lower().endswith((".html", ".htm")) and b"\x00" not in data[:4096]:
        ctype = "text/html"
    else:
        raise HTTPException(422, "attachments must be PDF or HTML")
    att = IntelAttachment(
        item_id=item.id,
        filename=name,
        content_type=ctype,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        data=data,
        created_by=p.user.username,
    )
    db.add(att)
    db.flush()
    audit.record(
        db,
        "intel.attachment_added",
        actor=p.user,
        request=request,
        target_type="intel",
        target_id=item.id,
        details={"filename": name, "sha256": att.sha256, "size": att.size},
    )
    db.commit()
    return {"id": att.id, "filename": att.filename, "size": att.size, "content_type": att.content_type}


@router.get("/attachments/{att_id}")
def get_attachment(
    att_id: int, p: Principal = Depends(VIEW), _s: Settings = Depends(enabled), db: Session = Depends(get_db)
) -> Response:
    att = db.get(IntelAttachment, att_id)
    if att is None or (att.item.tlp == "RED" and str(P.INTEL_MANAGE) not in p.permissions):
        raise HTTPException(404, "Attachment not found")
    # always a download (never rendered in the app origin), sandboxed if a browser renders it anyway
    return Response(
        att.data,
        media_type="application/octet-stream" if att.content_type == "text/html" else att.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{att.filename}"',
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ---- bulk import -------------------------------------------------------------------------------------------


async def _import_rows(file: UploadFile, sub: IntelSubscription) -> tuple[list, list, str]:
    data = await file.read(20_000_001)
    try:
        rows, fmt = svc.parse_import(data, file.filename or "import.json")
        ok, errors = svc.validate_import(rows, default_tlp=svc.redistribution(sub)["default_tlp"])
    except svc.IntelError as exc:
        raise HTTPException(422, str(exc)) from exc
    return ok, errors, fmt


@router.post("/import/preview")
async def import_preview(
    subscription_id: int = Form(...),
    file: UploadFile = File(...),
    p: Principal = Depends(INTEL),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ok, errors, fmt = await _import_rows(file, _get(db, subscription_id))
    sample = [{**r, "published_at": r["published_at"].isoformat() if r.get("published_at") else None} for r in ok[:10]]
    return {"format": fmt, "valid": len(ok), "errors": errors[:100], "error_count": len(errors), "sample": sample}


@router.post("/import")
async def import_commit(
    request: Request,
    subscription_id: int = Form(...),
    file: UploadFile = File(...),
    skip_invalid: bool = Form(False),
    p: Principal = Depends(INTEL),
    _s: Settings = Depends(enabled),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    sub = _get(db, subscription_id)
    ok, errors, fmt = await _import_rows(file, sub)
    if errors and not skip_invalid:
        raise HTTPException(422, f"{len(errors)} invalid row(s) — fix them or import with skip_invalid")
    for r in ok:
        svc.create_manual(db, sub, dict(r), actor=p.user.username)
    audit.record(
        db,
        "intel.imported",
        actor=p.user,
        request=request,
        target_type="subscription",
        target_id=sub.id,
        details={
            "format": fmt,
            "imported": len(ok),
            "skipped_invalid": len(errors),
            "filename": (file.filename or "")[:200],
        },
    )
    db.commit()
    return {"imported": len(ok), "skipped_invalid": len(errors), "format": fmt}


@router.get("/status")
def feature_status(_: Principal = Depends(current_principal), settings: Settings = Depends(settings_dep)) -> dict:
    """Lets the UI decide whether to show subscription screens (no data, any signed-in user)."""
    return {"enabled": settings.features.subscriptions}

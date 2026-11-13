"""Settings → Alerts & Scheduling."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.alerts import engine
from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import AlertEvent, AlertRule
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P
from exposurecatalyst.security.ssrf import UnsafeURLError, validate_outbound_url

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Criteria(BaseModel):
    min_severity: Severity | None = None
    cvss_min: float | None = Field(None, ge=0, le=10)
    epss_min: float | None = Field(None, ge=0, le=1)
    kev_added: bool = False
    vendors: list[str] = Field(default_factory=list, max_length=100)
    products: list[str] = Field(default_factory=list, max_length=100)
    keywords: list[str] = Field(default_factory=list, max_length=50)
    affected_assets: bool = False


class Recipients(BaseModel):
    emails: list[EmailStr] = Field(default_factory=list, max_length=200)
    user_ids: list[int] = Field(default_factory=list, max_length=500)
    role_ids: list[int] = Field(default_factory=list, max_length=50)


class RuleIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    enabled: bool = True
    criteria: Criteria
    recipients: Recipients = Field(default_factory=Recipients)
    channels: list[Literal["email", "slack", "teams"]] = Field(default_factory=lambda: ["email"])
    webhooks: dict[Literal["slack", "teams"], str] | None = Field(None, description="write-only; omit to keep")
    mode: Literal["immediate", "digest"] = "immediate"
    throttle_minutes: int = Field(60, ge=0, le=10_080)
    digest_minutes: int = Field(1440, ge=15, le=10_080)


class RuleOut(BaseModel):
    id: int
    name: str
    enabled: bool
    criteria: dict
    recipients: dict
    channels: list[str]
    webhooks_set: list[str]
    mode: str
    throttle_minutes: int
    digest_minutes: int
    last_delivered_at: datetime | None
    last_error: str | None
    pending: int
    total_matches: int


def _out(db: Session, r: AlertRule) -> RuleOut:
    pending = db.scalar(select(func.count()).where(AlertEvent.rule_id == r.id, AlertEvent.status == "pending")) or 0
    total = db.scalar(select(func.count()).where(AlertEvent.rule_id == r.id)) or 0
    return RuleOut(
        id=r.id,
        name=r.name,
        enabled=r.enabled,
        criteria=r.criteria,
        recipients=r.recipients,
        channels=r.channels,
        webhooks_set=sorted(engine.load_webhooks(r)),
        mode=r.mode,
        throttle_minutes=r.throttle_minutes,
        digest_minutes=r.digest_minutes,
        last_delivered_at=r.last_delivered_at,
        last_error=r.last_error,
        pending=pending,
        total_matches=total,
    )


def _apply(r: AlertRule, body: RuleIn, settings: Settings) -> None:
    c = body.criteria.model_dump()
    c = {k: v for k, v in c.items() if v not in (None, False, [])}
    if not c:
        raise HTTPException(422, "Add at least one criterion (otherwise every CVE would alert)")
    r.name, r.enabled, r.criteria = body.name.strip(), body.enabled, c
    r.recipients = body.recipients.model_dump(mode="json")
    r.channels, r.mode = list(dict.fromkeys(body.channels)), body.mode
    r.throttle_minutes, r.digest_minutes = body.throttle_minutes, body.digest_minutes
    if body.webhooks is not None:
        hooks = {**engine.load_webhooks(r)}
        for kind, url in body.webhooks.items():
            if url:
                try:
                    validate_outbound_url(
                        url, allowlist=engine.WEBHOOK_HOSTS[kind], resolve_dns=settings.ssrf_resolve_dns
                    )
                except UnsafeURLError as exc:
                    raise HTTPException(422, f"{kind} webhook rejected: {exc}") from exc
            hooks[kind] = url
        engine.store_webhooks(r, hooks)
    missing = [ch for ch in r.channels if ch in ("slack", "teams") and ch not in engine.load_webhooks(r)]
    if missing:
        raise HTTPException(422, f"Provide a webhook URL for: {', '.join(missing)}")
    if "email" in r.channels and not any(r.recipients.get(k) for k in ("emails", "user_ids", "role_ids")):
        raise HTTPException(422, "Email channel needs at least one recipient, user or role")


@router.get("", response_model=list[RuleOut])
def list_rules(_: Principal = Depends(require(P.SETTINGS_MANAGE)), db: Session = Depends(get_db)):
    return [_out(db, r) for r in db.scalars(select(AlertRule).order_by(AlertRule.name))]


@router.post("", response_model=RuleOut, status_code=201)
def create_rule(
    body: RuleIn,
    request: Request,
    p: Principal = Depends(require(P.SETTINGS_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> RuleOut:
    if db.scalar(select(AlertRule).where(func.lower(AlertRule.name) == body.name.strip().lower())):
        raise HTTPException(409, "A rule with that name exists")
    r = AlertRule(created_by=p.user.id, cursor_at=utcnow())  # only CVEs changing from now on
    _apply(r, body, settings)
    db.add(r)
    db.flush()
    audit.record(
        db,
        "alert.rule_created",
        actor=p.user,
        request=request,
        target_type="alert_rule",
        target_id=r.id,
        details={"name": r.name, "criteria": r.criteria, "channels": r.channels},
    )
    db.commit()
    return _out(db, r)


@router.put("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int,
    body: RuleIn,
    request: Request,
    p: Principal = Depends(require(P.SETTINGS_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> RuleOut:
    r = db.get(AlertRule, rule_id)
    if r is None:
        raise HTTPException(404, "Rule not found")
    _apply(r, body, settings)
    audit.record(
        db,
        "alert.rule_updated",
        actor=p.user,
        request=request,
        target_type="alert_rule",
        target_id=r.id,
        details={"name": r.name, "criteria": r.criteria, "channels": r.channels, "enabled": r.enabled},
    )
    db.commit()
    return _out(db, r)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(
    rule_id: int, request: Request, p: Principal = Depends(require(P.SETTINGS_MANAGE)), db: Session = Depends(get_db)
) -> None:
    r = db.get(AlertRule, rule_id)
    if r is None:
        raise HTTPException(404, "Rule not found")
    audit.record(
        db,
        "alert.rule_deleted",
        actor=p.user,
        request=request,
        target_type="alert_rule",
        target_id=r.id,
        details={"name": r.name},
    )
    db.delete(r)
    db.commit()


@router.post("/{rule_id}/run")
def run_rule(
    rule_id: int,
    request: Request,
    p: Principal = Depends(require(P.SETTINGS_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    """Evaluate now and deliver pending matches immediately (ignores throttle/digest)."""
    r = db.get(AlertRule, rule_id)
    if r is None:
        raise HTTPException(404, "Rule not found")
    matched = engine.evaluate(db)
    sent = engine.deliver(db, settings, rule_ids=[r.id], force=True)
    audit.record(
        db,
        "alert.rule_run",
        actor=p.user,
        request=request,
        target_type="alert_rule",
        target_id=r.id,
        details={"new_matches": matched, "delivered": sent},
    )
    db.commit()
    return {"new_matches": matched, "delivered": sent, "rule": _out(db, r).model_dump(mode="json")}


class EventOut(BaseModel):
    cve_id: str
    reason: str
    matched_at: datetime
    delivered_at: datetime | None
    status: str


@router.get("/{rule_id}/events", response_model=list[EventOut])
def rule_events(rule_id: int, _: Principal = Depends(require(P.SETTINGS_MANAGE)), db: Session = Depends(get_db)):
    rows = db.scalars(select(AlertEvent).where(AlertEvent.rule_id == rule_id).order_by(AlertEvent.id.desc()).limit(200))
    return [
        EventOut(
            cve_id=e.cve_id, reason=e.reason, matched_at=e.matched_at, delivered_at=e.delivered_at, status=e.status
        )
        for e in rows
    ]

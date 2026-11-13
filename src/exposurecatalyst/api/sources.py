from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.service import HEARTBEAT_KEY, SOURCE_LABELS, SOURCE_ORDER
from exposurecatalyst.models import AppSetting, JobRun, SourceState
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission

router = APIRouter(prefix="/api/sources", tags=["sources"])


class SourceOut(BaseModel):
    source: str
    label: str
    enabled: bool
    status: str
    health: str  # healthy | degraded | failing | pending | disabled
    interval_minutes: int
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    records_last_run: int
    refresh_pending: bool


class SourcesOut(BaseModel):
    scheduler_alive: bool
    scheduler_heartbeat_at: datetime | None
    sources: list[SourceOut]


def _health(s: SourceState, interval: int) -> str:
    if not s.enabled:
        return "disabled"
    if s.last_success_at is None:
        return "failing" if s.status == "error" else "pending"
    if s.status == "error":
        return "failing" if (s.consecutive_failures or 0) >= 3 else "degraded"
    if as_utc(s.last_success_at) < utcnow() - timedelta(minutes=interval * 3):
        return "degraded"
    return "healthy"


@router.get("", response_model=SourcesOut)
def list_sources(_: Principal = Depends(require(Permission.CVE_VIEW)), db: Session = Depends(get_db),
                 settings: Settings = Depends(settings_dep)) -> SourcesOut:
    out = []
    for name in SOURCE_ORDER:
        s = db.get(SourceState, name)
        if s is None:
            continue
        default = settings.news_interval_minutes if name == "news" else settings.fetch_interval_minutes
        interval = s.interval_minutes or default
        out.append(SourceOut(source=name, label=SOURCE_LABELS[name], enabled=s.enabled, status=s.status,
                             health=_health(s, interval), interval_minutes=interval,
                             last_attempt_at=s.last_attempt_at, last_success_at=s.last_success_at,
                             last_error=s.last_error, records_last_run=s.records_last_run,
                             refresh_pending=s.refresh_requested_at is not None))
    hb = db.get(AppSetting, HEARTBEAT_KEY)
    hb_at = datetime.fromisoformat(hb.value["at"]) if hb else None
    alive = hb_at is not None and hb_at > utcnow() - timedelta(seconds=settings.scheduler_tick_seconds * 3)
    return SourcesOut(scheduler_alive=alive, scheduler_heartbeat_at=hb_at, sources=out)


@router.post("/refresh", status_code=202)
def refresh(request: Request, source: str | None = Query(None, pattern="^(nvd|kev|epss|news)$"),
            p: Principal = Depends(require(Permission.CVE_REFRESH)), db: Session = Depends(get_db)) -> dict:
    names = [source] if source else list(SOURCE_ORDER)
    now = utcnow()
    for s in db.scalars(select(SourceState).where(SourceState.source.in_(names), SourceState.enabled.is_(True))):
        s.refresh_requested_at = now
    audit.record(db, "source.refresh_requested", actor=p.user, request=request, target_type="source",
                 target_id=",".join(names))
    db.commit()
    return {"queued": names, "message": "Refresh queued; the scheduler picks it up within a minute."}


class SourcePatch(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = Field(None, ge=5, le=10_080)


@router.patch("/{name}", response_model=dict)
def update_source(name: str, body: SourcePatch, request: Request,
                  p: Principal = Depends(require(Permission.SOURCE_MANAGE)), db: Session = Depends(get_db)) -> dict:
    s = db.get(SourceState, name)
    if s is None:
        raise HTTPException(404, "Unknown source")
    changes = body.model_dump(exclude_unset=True)
    before = {k: getattr(s, k) for k in changes}
    for k, v in changes.items():
        setattr(s, k, v)
    audit.record(db, "source.updated", actor=p.user, request=request, target_type="source", target_id=name,
                 details={"before": before, "after": changes})
    db.commit()
    return {"source": name, **changes}


class JobRunOut(BaseModel):
    id: int
    source: str
    trigger: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    records: int
    error: str | None


@router.get("/runs", response_model=list[JobRunOut])
def recent_runs(limit: int = Query(50, ge=1, le=500), _: Principal = Depends(require(Permission.CVE_VIEW)),
                db: Session = Depends(get_db)):
    rows = db.scalars(select(JobRun).order_by(JobRun.id.desc()).limit(limit))
    return [JobRunOut.model_validate(r, from_attributes=True) for r in rows]

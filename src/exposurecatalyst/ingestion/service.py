"""Orchestration: due-source detection, cross-process claim/lock, run bookkeeping and metrics."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import timedelta

import structlog
from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.ingestion.base import Source
from exposurecatalyst.ingestion.epss import EpssSource
from exposurecatalyst.ingestion.kev import KevSource
from exposurecatalyst.ingestion.nvd import NvdSource
from exposurecatalyst.models import AppSetting, JobRun, SourceState

log = structlog.get_logger(__name__)

# Order matters: EPSS runs after NVD/KEV so newly created CVEs get scored in the same tick.
SOURCE_ORDER = ("nvd", "kev", "epss", "news")
SOURCE_LABELS = {"nvd": "NVD API 2.0", "kev": "CISA KEV", "epss": "FIRST EPSS", "news": "Security news feeds"}
HEARTBEAT_KEY = "scheduler.heartbeat"

RUNS = Counter("excat_ingestion_runs_total", "Ingestion runs", ["source", "status"])
RECORDS = Counter("excat_ingestion_records_total", "Records ingested", ["source"])
DURATION = Histogram("excat_ingestion_duration_seconds", "Ingestion run duration", ["source"],
                     buckets=(1, 5, 15, 30, 60, 120, 300, 900, 1800))
LAST_SUCCESS = Gauge("excat_source_last_success_timestamp", "Last successful run (unix time)", ["source"])

SourceFactory = Callable[[str, Settings], Source]


def default_factory(name: str, settings: Settings) -> Source:
    if name == "news":
        from exposurecatalyst.news.ingest import NewsSource

        return NewsSource(settings)
    return {"nvd": NvdSource, "kev": KevSource, "epss": EpssSource}[name](settings)


def ensure_source_states(db: Session) -> None:
    have = set(db.scalars(select(SourceState.source)))
    for name in SOURCE_ORDER:
        if name not in have:
            db.add(SourceState(source=name, enabled=True, status="never", meta={}))
    db.flush()


def due_sources(db: Session, settings: Settings) -> list[str]:
    now = utcnow()
    due = []
    states = {s.source: s for s in db.scalars(select(SourceState))}
    for name in SOURCE_ORDER:
        s = states.get(name)
        if s is None or not s.enabled:
            continue
        default = settings.news_interval_minutes if name == "news" else settings.fetch_interval_minutes
        interval = timedelta(minutes=s.interval_minutes or default)
        if s.refresh_requested_at is not None or s.last_attempt_at is None or \
                as_utc(s.last_attempt_at) + interval <= now:
            due.append(name)
    return due


def claim(db: Session, name: str, settings: Settings) -> bool:
    """Atomically mark a source as running. Safe across processes and replicas."""
    now = utcnow()
    stale = now - timedelta(minutes=settings.job_stale_after_minutes)
    res = db.execute(
        update(SourceState)
        .where(SourceState.source == name,
               or_(SourceState.status != "running", SourceState.last_attempt_at < stale))
        .values(status="running", last_attempt_at=now, refresh_requested_at=None)
    )
    db.commit()
    return res.rowcount == 1


def _sanitize(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:1000]


def run_source(name: str, trigger: str, settings: Settings, session_factory: sessionmaker[Session],
               factory: SourceFactory = default_factory) -> JobRun | None:
    with session_factory() as db:
        if not claim(db, name, settings):
            log.info("source_already_running", source=name)
            return None
        job = JobRun(source=name, trigger=trigger, started_at=utcnow(), status="running")
        db.add(job)
        db.commit()
        state = db.get(SourceState, name)
        if state is None:
            raise RuntimeError(f"unknown source {name}")
        source = factory(name, settings)
        started = time.perf_counter()
        try:
            result = source.run(db, state, utcnow())
        except Exception as exc:  # noqa: BLE001 - record any failure as source health
            db.rollback()
            state = db.get(SourceState, name)
            job = db.get(JobRun, job.id)
            state.status = "error"
            state.last_error = _sanitize(exc)
            state.consecutive_failures = (state.consecutive_failures or 0) + 1
            job.status, job.error, job.finished_at = "error", state.last_error, utcnow()
            db.commit()
            RUNS.labels(name, "error").inc()
            log.error("source_run_failed", source=name, error=state.last_error)
            return job
        finally:
            source.close()
            DURATION.labels(name).observe(time.perf_counter() - started)
        now = utcnow()
        state.status, state.last_success_at, state.last_error = "ok", now, None
        state.consecutive_failures = 0
        state.records_last_run = result.records
        job.status, job.records, job.finished_at = "ok", result.records, now
        db.commit()
        RUNS.labels(name, "ok").inc()
        RECORDS.labels(name).inc(result.records)
        LAST_SUCCESS.labels(name).set(now.timestamp())
        log.info("source_run_ok", source=name, records=result.records, **{k: v for k, v in result.detail.items()
                                                                           if isinstance(v, int | str | bool)})
        return job


def heartbeat(db: Session) -> None:
    row = db.get(AppSetting, HEARTBEAT_KEY)
    value = {"at": utcnow().isoformat()}
    if row is None:
        db.add(AppSetting(key=HEARTBEAT_KEY, value=value, updated_by="scheduler"))
    else:
        row.value = value
    db.commit()


def tick(settings: Settings, session_factory: sessionmaker[Session],
         factory: SourceFactory = default_factory) -> list[str]:
    with session_factory() as db:
        heartbeat(db)
        due = due_sources(db, settings)
        triggers = {s.source: ("manual" if s.refresh_requested_at else "scheduled")
                    for s in db.scalars(select(SourceState))}
    for name in due:
        run_source(name, triggers.get(name, "scheduled"), settings, session_factory, factory)
    from exposurecatalyst.alerts.engine import run as run_alerts

    run_alerts(settings, session_factory)  # evaluate rules against what just changed; deliver due alerts
    return due

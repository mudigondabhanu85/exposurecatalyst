"""APScheduler wiring. A single fixed-rate tick decides what is due, so per-source intervals and
"Refresh now" requests take effect without restarting or signalling the scheduler process.

For scaled deployments, the same ``tick`` can be triggered by Amazon EventBridge Scheduler or
Celery beat; the DB claim in ``service.claim`` prevents duplicate runs either way.
"""

from __future__ import annotations

import contextlib
import os
import signal
import time
from pathlib import Path

import structlog
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.blocking import BlockingScheduler

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.ingestion.service import tick

log = structlog.get_logger(__name__)
# Container healthcheck heartbeat. Only written when EXCAT_SCHEDULER_HEARTBEAT is set (docker compose points it at
# the container's private tmpfs), so local runs behave exactly as before.
_HB = os.environ.get("EXCAT_SCHEDULER_HEARTBEAT", "")
HEARTBEAT: Path | None = Path(_HB) if _HB else None


def _heartbeat() -> None:
    """Liveness signal for `exposurecatalyst healthcheck scheduler` (no-follow write: never through a symlink)."""
    if HEARTBEAT is None:
        return
    with contextlib.suppress(OSError):
        fd = os.open(HEARTBEAT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(str(int(time.time())))


def _add_jobs(scheduler, settings: Settings) -> None:
    scheduler.add_job(
        tick,
        "interval",
        seconds=settings.scheduler_tick_seconds,
        args=[settings, get_session_factory()],
        id="ingestion-tick",
        max_instances=1,
        coalesce=True,
        next_run_time=utcnow(),
        replace_existing=True,
    )


def start_background(settings: Settings) -> BackgroundScheduler:
    sched = BackgroundScheduler(timezone="UTC")
    _add_jobs(sched, settings)
    sched.start()
    log.info("scheduler_started", mode="embedded")
    return sched


def run_forever(settings: Settings) -> None:
    sched = BlockingScheduler(timezone="UTC")
    _add_jobs(sched, settings)
    if HEARTBEAT is not None:
        sched.add_job(_heartbeat, "interval", seconds=30, id="heartbeat", next_run_time=utcnow(),
                      replace_existing=True)
    signal.signal(signal.SIGTERM, lambda *_: sched.shutdown(wait=False))
    log.info("scheduler_started", mode="standalone", tick_seconds=settings.scheduler_tick_seconds)
    sched.start()

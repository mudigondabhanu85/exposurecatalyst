"""FIRST EPSS — exploit prediction scores. Per-CVE API for small sets, bulk CSV for large ones."""

from __future__ import annotations

import csv
import gzip
import io
from datetime import datetime, timedelta

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.ingestion.base import RunResult, chunked, load_cves
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.ingestion.normalize import parse_date
from exposurecatalyst.models import Cve, CveEvent, SourceState

SOURCE = "epss"
API_BATCH = 100
RECHECK_AFTER = timedelta(hours=20)  # EPSS publishes once a day
EVENT_DELTA = 0.10  # record a timeline event when probability moves ≥ 10 points


class EpssSource:
    name = SOURCE

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, sleep=None):
        kwargs = {"sleep": sleep} if sleep else {}
        self.settings = settings
        self.client = SourceClient(SOURCE, settings, rate=60, per=60.0, transport=transport, **kwargs)

    def close(self) -> None:
        self.client.close()

    def _apply(self, cve: Cve, score: float, pct: float, day, now: datetime) -> None:
        old = cve.epss_score
        cve.epss_score, cve.epss_percentile, cve.epss_date = score, pct, day
        cve.epss_checked_at = now
        cve.set_prov("epss", SOURCE, now)
        if old is not None and abs(score - old) >= EVENT_DELTA:
            cve.events.append(CveEvent(event_type="EPSS_CHANGED", source=SOURCE, occurred_at=now,
                                       detail={"from": old, "to": score}))

    def run(self, db: Session, state: SourceState, now: datetime) -> RunResult:
        stale_ids = list(db.scalars(select(Cve.cve_id).where(
            or_(Cve.epss_checked_at.is_(None), Cve.epss_checked_at < now - RECHECK_AFTER))))
        if not stale_ids:
            return RunResult(0, {"mode": "noop"})
        if len(stale_ids) > self.settings.epss_bulk_threshold:
            return self._bulk(db, set(stale_ids), now)
        return self._api(db, stale_ids, now)

    def _api(self, db: Session, ids: list[str], now: datetime) -> RunResult:
        result = RunResult(detail={"mode": "api", "requested": len(ids)})
        for batch in chunked(sorted(ids), API_BATCH):
            body = self.client.get(self.settings.epss_api_url, params={"cve": ",".join(batch)}).json()
            rows = load_cves(db, batch)
            for item in body.get("data", []):
                cve = rows.get(str(item.get("cve", "")).upper())
                if cve is not None:
                    self._apply(cve, float(item["epss"]), float(item["percentile"]), parse_date(item.get("date")), now)
                    result.records += 1
            for cve in rows.values():  # not scored yet (brand-new CVE) → don't re-ask every hour
                cve.epss_checked_at = now
            db.commit()
        return result

    def _bulk(self, db: Session, wanted: set[str], now: datetime) -> RunResult:
        resp = self.client.get(self.settings.epss_bulk_url)
        text = gzip.decompress(resp.content).decode("utf-8")
        lines = text.splitlines()
        day = None
        if lines and lines[0].startswith("#"):
            for part in lines[0].lstrip("#").split(","):
                if part.startswith("score_date:"):
                    day = parse_date(part.split(":", 1)[1])
            lines = lines[1:]
        scores = {}
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            cid = row.get("cve", "").upper()
            if cid in wanted:
                scores[cid] = (float(row["epss"]), float(row["percentile"]))
        result = RunResult(detail={"mode": "bulk", "requested": len(wanted)})
        for batch in chunked(sorted(wanted), 1000):
            for cid, cve in load_cves(db, batch).items():
                if cid in scores:
                    self._apply(cve, *scores[cid], day, now)
                    result.records += 1
                else:
                    cve.epss_checked_at = now
            db.commit()
        return result

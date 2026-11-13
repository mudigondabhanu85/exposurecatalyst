"""NVD CVE API 2.0 — incremental fetch by lastModified window."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc
from exposurecatalyst.ingestion.base import RunResult, load_cves
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.ingestion.normalize import NormalizedCve, derive_title, parse_nvd_cve
from exposurecatalyst.models import Cve, CveEvent, CveProduct, SourceState

log = structlog.get_logger(__name__)
MAX_WINDOW = timedelta(days=120)  # NVD API limit for lastMod ranges
OVERLAP = timedelta(minutes=5)  # tolerate clock skew / late-indexed records
PAGE_SIZE = 2000
SOURCE = "nvd"


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    cur = start
    while cur < end:
        nxt = min(cur + MAX_WINDOW, end)
        yield cur, nxt
        cur = nxt


def apply_nvd(cve: Cve, n: NormalizedCve, now: datetime, cvss_order: list[str]) -> dict[str, Any] | None:
    """Merge NVD data into ``cve``. Returns a dict of material changes (for the timeline) or None."""
    before = (cve.cvss_score, cve.severity, cve.vuln_status, len(cve.products))
    primary = n.primary_cvss(cvss_order)

    cve.description = n.description
    cve.vuln_status = n.vuln_status
    cve.published_at = n.published_at
    cve.last_modified_at = n.last_modified_at
    cve.cvss_metrics = n.cvss_metrics
    cve.cvss_score = primary["score"] if primary else None
    cve.cvss_version = primary["version"] if primary else None
    cve.cvss_vector = primary["vector"] if primary else None
    cve.severity = primary["severity"] if primary else "UNKNOWN"
    cve.cwes = n.cwes
    cve.references = n.references
    cve.patch_refs = n.patch_refs
    nvd_exploits = n.exploit_refs
    cve.exploit_refs = sorted(set(nvd_exploits))
    cve.exploit_available = bool(nvd_exploits) or cve.kev
    if not cve.title or (cve.provenance or {}).get("title", {}).get("source") == SOURCE:
        cve.title = (n.kev_name or derive_title(n.description, n.cve_id))[:512]
        cve.set_prov("title", SOURCE, now)
    for f in ("description", "vuln_status", "published_at", "last_modified_at", "cvss", "cwes",
              "references", "products", "patch_refs"):
        cve.set_prov(f, SOURCE, now)
    if nvd_exploits:
        cve.set_prov("exploit_available", SOURCE, now)

    if n.products:
        # NVD CPE data is authoritative; it replaces earlier rows (incl. KEV vendor/product stubs).
        cve.products.clear()
        for p in n.products:
            cve.products.append(CveProduct(source=SOURCE, **p.__dict__))

    after = (cve.cvss_score, cve.severity, cve.vuln_status, len(cve.products))
    if before == after:
        return None
    return {"cvss_score": [before[0], after[0]], "severity": [before[1], after[1]],
            "vuln_status": [before[2], after[2]], "product_count": [before[3], after[3]]}


class NvdSource:
    name = SOURCE

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, sleep=None):
        key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
        rate = 50 if key else 5  # requests per rolling 30 s, per NVD policy
        kwargs = {"sleep": sleep} if sleep else {}
        self.settings = settings
        self.client = SourceClient(SOURCE, settings, rate=rate, per=30.0,
                                   headers={"apiKey": key} if key else None, transport=transport, **kwargs)

    def close(self) -> None:
        self.client.close()

    def fetch(self, start: datetime, end: datetime) -> Iterator[list[dict[str, Any]]]:
        index = 0
        while True:
            resp = self.client.get(self.settings.nvd_base_url, params={
                "lastModStartDate": _fmt(start), "lastModEndDate": _fmt(end),
                "startIndex": index, "resultsPerPage": PAGE_SIZE,
            })
            body = resp.json()
            vulns = body.get("vulnerabilities", [])
            yield vulns
            index += len(vulns)
            if not vulns or index >= int(body.get("totalResults", 0)):
                return

    def run(self, db: Session, state: SourceState, now: datetime) -> RunResult:
        start = (as_utc(state.cursor_at) - OVERLAP) if state.cursor_at else now - timedelta(
            days=self.settings.initial_backfill_days)
        return self.ingest_range(db, state, start, now)

    def ingest_range(self, db: Session, state: SourceState, start: datetime, end: datetime) -> RunResult:
        result = RunResult(detail={"created": 0, "updated": 0, "skipped": 0})
        order = self.settings.cvss_version_order
        for w_start, w_end in windows(start, end):
            for page in self.fetch(w_start, w_end):
                parsed: list[NormalizedCve] = []
                for item in page:
                    try:
                        parsed.append(parse_nvd_cve(item))
                    except (KeyError, ValueError, TypeError) as exc:
                        result.detail["skipped"] += 1
                        log.warning("nvd_record_skipped", error=str(exc)[:200])
                existing = load_cves(db, [p.cve_id for p in parsed])
                for n in parsed:
                    cve = existing.get(n.cve_id)
                    if cve is None:
                        cve = Cve(cve_id=n.cve_id, provenance={}, products=[], cvss_metrics=[])
                        db.add(cve)
                        apply_nvd(cve, n, end, order)
                        cve.events.append(CveEvent(event_type="PUBLISHED", source=SOURCE,
                                                   occurred_at=n.published_at or end, detail={}))
                        existing[n.cve_id] = cve
                        result.detail["created"] += 1
                    else:
                        if cve.last_modified_at and n.last_modified_at and \
                                as_utc(cve.last_modified_at) >= n.last_modified_at:
                            continue
                        change = apply_nvd(cve, n, end, order)
                        if change:
                            cve.events.append(CveEvent(event_type="MODIFIED", source=SOURCE,
                                                       occurred_at=n.last_modified_at or end, detail=change))
                        result.detail["updated"] += 1
                    result.records += 1
                db.commit()  # commit per page: progress survives a later failure
            state.cursor_at = w_end  # advance only after a whole window succeeded
            db.commit()
        return result

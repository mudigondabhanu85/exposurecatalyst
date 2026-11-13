"""CISA Known Exploited Vulnerabilities catalogue."""

from __future__ import annotations

from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.ingestion.base import RunResult, load_cves
from exposurecatalyst.ingestion.http import SourceClient, SourceHTTPError
from exposurecatalyst.ingestion.normalize import CVE_ID_RE, parse_date
from exposurecatalyst.models import Cve, CveEvent, CveProduct, SourceState

SOURCE = "kev"
MIN_SANE_ENTRIES = 100  # guard: never mass-unflag KEV because of a truncated/empty response


class KevSource:
    name = SOURCE

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, sleep=None):
        kwargs = {"sleep": sleep} if sleep else {}
        self.settings = settings
        self.client = SourceClient(SOURCE, settings, rate=10, per=60.0, transport=transport, **kwargs)

    def close(self) -> None:
        self.client.close()

    def run(self, db: Session, state: SourceState, now: datetime) -> RunResult:
        meta = dict(state.meta or {})
        headers = {"If-None-Match": meta["etag"]} if meta.get("etag") else None
        resp = self.client.get(self.settings.kev_url, headers=headers, ok_statuses=(200, 304))
        if resp.status_code == 304:
            return RunResult(0, {"unchanged": True})

        body = resp.json()
        entries = {}
        for v in body.get("vulnerabilities", []):
            cid = str(v.get("cveID", "")).strip().upper()
            if CVE_ID_RE.match(cid):
                entries[cid] = v
        if len(entries) < MIN_SANE_ENTRIES:
            raise SourceHTTPError(f"kev: catalogue has only {len(entries)} entries — refusing to apply")

        result = RunResult(detail={"added": 0, "removed": 0, "catalog_version": body.get("catalogVersion")})
        existing = load_cves(db, entries.keys())
        for cid, v in entries.items():
            cve = existing.get(cid)
            if cve is None:  # KEV can list a CVE before NVD has processed it
                cve = Cve(cve_id=cid, description=v.get("shortDescription"), provenance={}, products=[],
                          cvss_metrics=[])
                cve.set_prov("description", SOURCE, now)
                cve.products.append(CveProduct(vendor=str(v.get("vendorProject", ""))[:128],
                                               product=str(v.get("product", ""))[:256], source=SOURCE))
                db.add(cve)
            newly = not cve.kev
            cve.kev = True
            cve.kev_date_added = parse_date(v.get("dateAdded"))
            cve.kev_due_date = parse_date(v.get("dueDate"))
            cve.kev_required_action = v.get("requiredAction")
            cve.kev_ransomware_use = (v.get("knownRansomwareCampaignUse") or "")[:16] or None
            cve.exploit_available = True
            if v.get("vulnerabilityName"):
                cve.title = str(v["vulnerabilityName"])[:512]
                cve.set_prov("title", SOURCE, now)
            for f in ("kev", "kev_due_date", "kev_required_action", "exploit_available"):
                cve.set_prov(f, SOURCE, now)
            if newly:
                cve.events.append(CveEvent(event_type="KEV_ADDED", source=SOURCE, occurred_at=now,
                                           detail={"date_added": v.get("dateAdded"), "due_date": v.get("dueDate")}))
                result.detail["added"] += 1
            result.records += 1

        for cve in db.scalars(select(Cve).where(Cve.kev.is_(True))):
            if cve.cve_id not in entries:
                cve.kev = False
                cve.exploit_available = bool(cve.exploit_refs)
                cve.set_prov("kev", SOURCE, now)
                cve.events.append(CveEvent(event_type="KEV_REMOVED", source=SOURCE, occurred_at=now, detail={}))
                result.detail["removed"] += 1

        meta["etag"] = resp.headers.get("etag")
        meta["catalog_version"] = body.get("catalogVersion")
        state.meta = meta
        db.commit()
        return result

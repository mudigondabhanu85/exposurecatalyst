"""Advisory domain logic: IDs, validation matrix, de-duplication, subjects, workflow rules."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import (
    Advisory,
    AdvisoryAsset,
    AdvisorySequence,
    AdvisorySourceStatus,
    AdvisoryTemplate,
    AdvisoryTemplateVersion,
    Cve,
)
from exposurecatalyst.models.advisory import APPROVED, DRAFT

SLA_DAYS = {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90}
TEMPLATE_FOR_SEVERITY = {"CRITICAL": "critical", "HIGH": "high"}
_CRLF = re.compile(r"[\r\n\t\x00-\x1f\x7f]+")


class WorkflowError(ValueError):
    """Raised when an action is not allowed in the advisory's current state."""


# ---- IDs ----------------------------------------------------------------------------------------

def allocate_advisory_id(db: Session, now: datetime | None = None) -> str:
    """Next EXCAT-YYYY-NNNN. Row lock serialises concurrent allocations (no gaps reused)."""
    year = (now or utcnow()).year
    for _ in range(3):
        stmt = select(AdvisorySequence).where(AdvisorySequence.year == year).with_for_update()
        seq = db.execute(stmt).scalar_one_or_none()
        if seq is None:
            try:
                with db.begin_nested():
                    db.add(AdvisorySequence(year=year, last_value=0))
            except IntegrityError:
                continue  # another transaction created it — retry and lock it
            continue
        seq.last_value += 1
        db.flush()
        return f"EXCAT-{year}-{seq.last_value:04d}"
    raise RuntimeError("could not allocate advisory id")


# ---- matrix & de-duplication ----------------------------------------------------------------------

@dataclass
class MatrixRow:
    source: str
    validated: str  # "Yes" | "No" | "Not Integrated"
    asset_count: int
    last_checked: datetime | None
    manual: bool


@dataclass
class Exposure:
    rows: list[MatrixRow]
    unique_assets: list[dict] = field(default_factory=list)
    total_unique: int = 0
    manual_uncounted: int = 0  # manual per-source counts without asset rows (cannot be de-duplicated)


def _norm_host(h: str | None) -> str | None:
    if not h:
        return None
    h = h.strip().lower().rstrip(".")
    return h or None


def _norm_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip().lower() or None


def dedupe_assets(assets: list[AdvisoryAsset]) -> list[dict]:
    """Merge rows that share a hostname, IP or cloud resource ID (union-find across sources)."""
    parent = list(range(len(assets)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[tuple[str, str], int] = {}
    for i, a in enumerate(assets):
        keys = [("h", _norm_host(a.hostname)), ("i", _norm_ip(a.ip_address)),
                ("r", (a.resource_id or "").strip().lower() or None)]
        for k in keys:
            if k[1] is None:
                continue
            if k in seen:
                parent[find(i)] = find(seen[k])
            else:
                seen[k] = i
    groups: dict[int, list[AdvisoryAsset]] = {}
    for i, a in enumerate(assets):
        groups.setdefault(find(i), []).append(a)

    merged = []
    for members in groups.values():
        def first(attr: str, members=members):
            return next((getattr(m, attr) for m in members if getattr(m, attr)), None)

        merged.append({
            "hostname": first("hostname"), "ip_address": first("ip_address"), "os": first("os"),
            "cloud_account": first("cloud_account"), "resource_id": first("resource_id"), "owner": first("owner"),
            "business_unit": first("business_unit"), "environment": first("environment"),
            "detection_date": min((m.detection_date for m in members if m.detection_date), default=None),
            "sources": sorted({m.source for m in members}),
            "source_refs": sorted({m.source_ref for m in members if m.source_ref}),
            "manual": any(m.is_manual for m in members),
        })
    return sorted(merged, key=lambda r: (r["hostname"] or "", r["ip_address"] or ""))


def exposure(adv: Advisory) -> Exposure:
    """Validated = Yes ONLY when assets were actually identified for that source."""
    by_source: dict[str, list[AdvisoryAsset]] = {}
    for a in adv.assets:
        by_source.setdefault(a.source, []).append(a)
    rows, uncounted = [], 0
    known = {s.source for s in adv.sources}
    extra = [AdvisorySourceStatus(source=s, integrated=False) for s in by_source if s not in known]
    statuses = list(adv.sources) + extra
    for st in statuses:
        found = by_source.get(st.source, [])
        manual = st.manual_count is not None or any(a.is_manual for a in found)
        count = len(found) if found else (st.manual_count or 0)
        if not found and st.manual_count:
            uncounted += st.manual_count
        if count > 0:
            validated = "Yes"
        elif st.integrated or st.manual_count is not None:
            validated = "No"
        else:
            validated = "Not Integrated"
        last = as_utc(st.last_checked) or (max((as_utc(a.created_at) for a in found), default=None) if found else None)
        rows.append(MatrixRow(st.source, validated, count, last, manual))
    unique = dedupe_assets(list(adv.assets))
    return Exposure(rows=rows, unique_assets=unique, total_unique=len(unique) + uncounted, manual_uncounted=uncounted)


# ---- subject & defaults -----------------------------------------------------------------------

def clean_header(value: str, limit: int = 300) -> str:
    """Header-injection guard: no CR/LF/control characters in subjects or names."""
    return _CRLF.sub(" ", value).strip()[:limit]


def primary_product(cve: Cve | None, adv: Advisory | None = None) -> str:
    if adv and adv.affected_products:
        return adv.affected_products.split(",")[0].split("\n")[0].strip()[:60]
    if cve and cve.products:
        p = cve.products[0]
        return f"{p.vendor} {p.product}".replace("_", " ").title()[:60]
    return "Multiple products"


def default_subject(adv: Advisory, cve: Cve | None, asset_total: int) -> str:
    n = f"{asset_total} asset{'s' if asset_total != 1 else ''} affected"
    return clean_header(f"[{adv.severity}] {adv.advisory_id} Security Advisory: {adv.cve_id} – "
                        f"{primary_product(cve, adv)} – {n}")


def pick_template(db: Session, severity: str, template_id: int | None = None) -> AdvisoryTemplateVersion:
    stmt = select(AdvisoryTemplate)
    stmt = stmt.where(AdvisoryTemplate.id == template_id) if template_id else stmt.where(
        AdvisoryTemplate.kind == TEMPLATE_FOR_SEVERITY.get(severity, "informational"))
    tpl = db.scalars(stmt).first()
    if tpl is None:
        raise WorkflowError("template not found")
    approved = [v for v in tpl.versions if v.status == APPROVED]
    if not approved:
        raise WorkflowError(f"template '{tpl.name}' has no approved version")
    return approved[-1]


def new_advisory(db: Session, cve: Cve, *, user_id: int, sources: list[str],
                 template_id: int | None = None) -> Advisory:
    severity = cve.severity if cve.severity in SLA_DAYS else ("HIGH" if cve.kev else "MEDIUM")
    tv = pick_template(db, severity, template_id)
    sla_due = date.today() + timedelta(days=SLA_DAYS.get(severity, 30))
    # CISA's KEV due date is used only while it is still ahead (older KEV entries have past dates).
    due = min(cve.kev_due_date, sla_due) if cve.kev_due_date and cve.kev_due_date >= date.today() else sla_due
    products = sorted({f"{p.vendor} {p.product}".replace("_", " ").title() for p in cve.products})
    remediation = cve.kev_required_action or "Apply the vendor security update referenced below to all affected assets."
    if cve.patch_refs:
        remediation += "\n\nVendor references:\n" + "\n".join(cve.patch_refs[:5])
    adv = Advisory(
        advisory_id=allocate_advisory_id(db), cve_id=cve.cve_id, template_version_id=tv.id, status=DRAFT,
        severity=severity, title=cve.title, summary=cve.description, affected_products=", ".join(products[:10]),
        remediation=remediation, sla_due_date=due, created_by=user_id, subject="",
        sources=[AdvisorySourceStatus(source=s, integrated=False) for s in sources],
        to_addrs=[], cc_addrs=[], bcc_addrs=[], assets=[],
    )
    adv.template_version = tv
    adv.subject = default_subject(adv, cve, 0)
    db.add(adv)
    db.flush()
    return adv


# ---- workflow --------------------------------------------------------------------------------

def require_status(adv: Advisory, *allowed: str) -> None:
    if adv.status not in allowed:
        raise WorkflowError(f"advisory is '{adv.status}'; this action needs: {', '.join(allowed)}")


def can_approve(adv: Advisory, approver_id: int) -> None:
    require_status(adv, "in_review")
    if adv.created_by == approver_id:
        raise WorkflowError("segregation of duties: you cannot approve an advisory you created")


def all_recipients(adv: Advisory) -> list[str]:
    return list(dict.fromkeys([*adv.to_addrs, *adv.cc_addrs, *adv.bcc_addrs]))

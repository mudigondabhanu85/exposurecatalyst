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

SLA_DAYS = {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90}  # fallback when settings are unavailable
DETECTION_METHODS = {
    "vulnerability_check": "Vulnerability check",
    "software_inventory": "Software inventory",
    "asset_inventory": "Asset inventory / CMDB",
    "manual": "Manual analysis",
}
# Integration catalog category → how that kind of tool usually identifies affected assets.
CATEGORY_METHOD = {"Asset inventory (CAASM)": "asset_inventory"}
DEFAULT_OWNER_ACTIONS = """- Engage the divisional support organisations responsible for the affected assets.
- Ensure support teams have the information, access, maintenance windows and resources to remediate.
- Help resolve systems with unidentified support ownership.
- Track remediation progress and escalate blockers as appropriate.
- Coordinate exception requests where remediation cannot be completed within policy timelines."""
DEFAULT_SUPPORT_ACTIONS = """- Use the Support group column in the attached inventory to see who remediates each system.
- Apply the vendor-fixed version to every affected system (reboot where the update requires it).
- Re-scan or re-check remediated systems and report any that cannot be remediated in time."""
# Names for the CWE IDs most often seen in advisories (NVD records carry only the ID).
CWE_NAMES = {
    "CWE-20": "Improper input validation", "CWE-22": "Path traversal", "CWE-77": "Command injection",
    "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting (XSS)", "CWE-89": "SQL injection",
    "CWE-94": "Code injection", "CWE-119": "Memory buffer overflow", "CWE-120": "Classic buffer overflow",
    "CWE-121": "Stack-based buffer overflow", "CWE-122": "Heap-based buffer overflow",
    "CWE-125": "Out-of-bounds read", "CWE-190": "Integer overflow", "CWE-200": "Information exposure",
    "CWE-269": "Improper privilege management", "CWE-276": "Incorrect default permissions",
    "CWE-284": "Improper access control", "CWE-287": "Improper authentication",
    "CWE-306": "Missing authentication for a critical function", "CWE-352": "Cross-site request forgery (CSRF)",
    "CWE-362": "Race condition due to improper synchronization", "CWE-400": "Uncontrolled resource consumption",
    "CWE-401": "Memory leak", "CWE-416": "Use after free", "CWE-434": "Unrestricted file upload",
    "CWE-476": "NULL pointer dereference", "CWE-502": "Deserialization of untrusted data",
    "CWE-611": "XML external entity (XXE)", "CWE-639": "Authorization bypass via user-controlled key",
    "CWE-787": "Out-of-bounds write", "CWE-798": "Hard-coded credentials", "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization", "CWE-918": "Server-side request forgery (SSRF)",
    "CWE-1321": "Prototype pollution",
}
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
    shown: bool = True
    check_available: bool | None = None  # None = unknown / not stated
    detection_method: str | None = None
    note: str | None = None  # analyst note, else ``finding`` is used in the email
    finding: str = ""  # generated one-sentence result for this tool

    @property
    def check_label(self) -> str:
        return {True: "Yes", False: "No", None: "—"}[self.check_available]

    @property
    def method_label(self) -> str:
        return DETECTION_METHODS.get(self.detection_method or "", "")


@dataclass
class Exposure:
    rows: list[MatrixRow]
    unique_assets: list[dict] = field(default_factory=list)
    total_unique: int = 0
    manual_uncounted: int = 0  # manual per-source counts without asset rows (cannot be de-duplicated)
    hidden: list[MatrixRow] = field(default_factory=list)  # tools the analyst excluded from the email

    @property
    def methodology(self) -> list[str]:
        """Plain-language account of how exposure was established (one sentence per tool)."""
        return [r.finding for r in self.rows if r.finding]

    @property
    def potential(self) -> bool:
        """True when affected assets rest on inventory/version matching rather than a vulnerability check."""
        return any(r.asset_count and r.detection_method in ("software_inventory", "asset_inventory")
                   for r in self.rows)


def _finding(r: MatrixRow) -> str:
    n = r.asset_count
    assets = f"{n} asset{'s' if n != 1 else ''}"
    if r.validated == "Not Integrated" and r.check_available is None:
        return ""
    if r.detection_method in ("software_inventory", "asset_inventory"):
        src = "software inventory" if r.detection_method == "software_inventory" else "asset inventory / CMDB"
        lead = ("Checks are currently unavailable in {s}; " if r.check_available is False else
                "Checks are available in {s}, but no vulnerable instances were detected; "
                if r.check_available and n == 0 else "In {s}, ").format(s=r.source)
        if n:
            return (lead + f"{src} analysis identified {assets} as potentially vulnerable based on detected "
                    "software versions.")
        return lead + f"{src} analysis found no potentially vulnerable assets."
    if r.check_available is False:
        return f"Checks are currently unavailable in {r.source}."
    if n:
        how = "vulnerability checks" if r.detection_method in (None, "vulnerability_check") else "manual analysis"
        return f"{r.source} {how} identified {assets} as vulnerable."
    if r.check_available:
        return f"Vulnerability checks are available in {r.source}; however, no vulnerable instances were identified."
    if r.validated == "No":
        return f"{r.source} reported no affected assets."
    return ""


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
            "support_group": first("support_group"), "asset_class": first("asset_class"),
            "detection_methods": sorted({DETECTION_METHODS.get(m.detection_method, m.detection_method)
                                         for m in members if m.detection_method}),
            "detection_date": min((m.detection_date for m in members if m.detection_date), default=None),
            "sources": sorted({m.source for m in members}),
            "source_refs": sorted({m.source_ref for m in members if m.source_ref}),
            "manual": any(m.is_manual for m in members),
        })
    return sorted(merged, key=lambda r: (r["hostname"] or "", r["ip_address"] or ""))


def exposure(adv: Advisory) -> Exposure:
    """Validated = Yes ONLY when assets were actually identified for that source.

    Tools the analyst hid (``shown`` false) are left out of the matrix, the asset list and the totals, so the
    email, Excel file and subject all describe the same set of tools; they are returned in ``hidden``.
    """
    by_source: dict[str, list[AdvisoryAsset]] = {}
    for a in adv.assets:
        by_source.setdefault(a.source, []).append(a)
    rows, hidden, uncounted = [], [], 0
    known = {s.source for s in adv.sources}
    extra = [AdvisorySourceStatus(source=s, integrated=False, shown=True) for s in by_source if s not in known]
    statuses = list(adv.sources) + extra
    for st in statuses:
        found = by_source.get(st.source, [])
        manual = st.manual_count is not None or any(a.is_manual for a in found)
        count = len(found) if found else (st.manual_count or 0)
        if count > 0:
            validated = "Yes"
        elif st.integrated or st.manual_count is not None:
            validated = "No"
        else:
            validated = "Not Integrated"
        last = as_utc(st.last_checked) or (max((as_utc(a.created_at) for a in found), default=None) if found else None)
        methods = {a.detection_method for a in found if a.detection_method}
        method = st.detection_method or (methods.pop() if len(methods) == 1 else None)
        check = st.check_available
        if check is None and count and method in (None, "vulnerability_check") and not manual:
            check = True  # an integration that returned vulnerable assets evidently has a check
        row = MatrixRow(st.source, validated, count, last, manual, shown=st.shown is not False,
                        check_available=check, detection_method=method, note=(st.note or "").strip() or None)
        row.finding = _finding(row)
        if not row.shown:
            hidden.append(row)
            continue
        if not found and st.manual_count:
            uncounted += st.manual_count
        rows.append(row)
    hidden_names = {r.source for r in hidden}
    unique = dedupe_assets([a for a in adv.assets if a.source not in hidden_names])
    return Exposure(rows=rows, unique_assets=unique, total_unique=len(unique) + uncounted,
                    manual_uncounted=uncounted, hidden=hidden)


def shown_assets(adv: Advisory) -> list[AdvisoryAsset]:
    hidden = {s.source for s in adv.sources if s.shown is False}
    return [a for a in adv.assets if a.source not in hidden]


# ---- CVE facts for exposure-analysis emails ----------------------------------------------------

def _pretty_product(vendor: str, product: str) -> str:
    name = product.replace("_", " ").title()
    v = vendor.replace("_", " ").title()
    return name if name.lower().startswith(v.lower()) else f"{v} {name}"


def version_range(p) -> str:
    lo = (f"from {p.version_start_including}" if p.version_start_including else
          f"after {p.version_start_excluding}" if p.version_start_excluding else "")
    hi = (f"before {p.version_end_excluding}" if p.version_end_excluding else
          f"up to and including {p.version_end_including}" if p.version_end_including else "")
    if lo or hi:
        return " ".join(x for x in (lo, hi) if x).capitalize()
    parts = (p.cpe or "").split(":")
    ver = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else ""
    return ver or "All versions"


def product_versions(cve: Cve | None, limit: int = 25) -> list[dict[str, str]]:
    """Affected products with version ranges from the CVE's CPE matches (vulnerable entries only)."""
    if cve is None:
        return []
    seen, out = set(), []
    for p in cve.products:
        if not p.vulnerable:
            continue
        row = (_pretty_product(p.vendor, p.product), version_range(p))
        if row not in seen:
            seen.add(row)
            out.append({"product": row[0], "versions": row[1]})
    return out[:limit]


def vuln_type(cve: Cve | None) -> str | None:
    cwes = [c for c in (cve.cwes if cve else []) or [] if c.startswith("CWE-")]
    if not cwes:
        return None
    return "; ".join(f"{CWE_NAMES[c]} ({c})" if c in CWE_NAMES else c for c in cwes[:3])


_REF_ORDER = ("Vendor Advisory", "Patch", "Mitigation", "Third Party Advisory", "Exploit")


def references(cve: Cve | None, cve_id: str, limit: int = 8) -> list[dict[str, str]]:
    """NVD first, then vendor advisories / patches. Only http(s) links (normalize drops anything else)."""
    out = [{"label": f"NVD – {cve_id}", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}]
    refs = [r for r in (cve.references if cve else []) or [] if str(r.get("url", "")).startswith(("https://", "http://"))]

    def rank(r: dict) -> int:
        tags = r.get("tags") or []
        return min((i for i, t in enumerate(_REF_ORDER) if t in tags), default=len(_REF_ORDER))

    for r in sorted(refs, key=rank):
        if len(out) >= limit:
            break
        url = r["url"]
        host = url.split("/")[2] if url.count("/") >= 2 else url
        tags = [t for t in (r.get("tags") or []) if t in _REF_ORDER]
        out.append({"label": f"{host}{' – ' + ', '.join(tags) if tags else ''}", "url": url})
    return out


def sla_days(severity: str) -> int:
    try:
        from exposurecatalyst.config import get_settings

        table = {k.upper(): v for k, v in get_settings().advisory_sla_days.items()}
    except Exception:  # noqa: BLE001 - settings unavailable (scripts) → built-in defaults
        table = SLA_DAYS
    return table.get(severity, SLA_DAYS.get(severity, 30))


def remediation_timeframes(adv: Advisory) -> list[dict]:
    """[{asset_class, days, due}] for the advisory's severity from settings; [] when none configured."""
    from exposurecatalyst.config import get_settings

    policy = {k.upper(): v for k, v in get_settings().advisory_remediation_timeframes.items()}
    start = (adv.created_at.date() if adv.created_at else date.today())
    return [{"asset_class": cls, "days": int(days), "due": start + timedelta(days=int(days))}
            for cls, days in (policy.get(adv.severity) or {}).items()]


def default_method(category: str | None) -> str:
    return CATEGORY_METHOD.get(category or "", "vulnerability_check")


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


def _source_specs(sources: list[str] | list[tuple[str, str | None]]) -> list[tuple[str, str | None]]:
    out: dict[str, str | None] = {}
    for s in sources:
        name, method = (s, None) if isinstance(s, str) else s
        out.setdefault(name, method)
    return list(out.items())


def new_advisory(db: Session, cve: Cve, *, user_id: int, sources: list[str] | list[tuple[str, str | None]],
                 template_id: int | None = None) -> Advisory:
    severity = cve.severity if cve.severity in SLA_DAYS else ("HIGH" if cve.kev else "MEDIUM")
    tv = pick_template(db, severity, template_id)
    sla_due = date.today() + timedelta(days=sla_days(severity))
    # CISA's KEV due date is used only while it is still ahead (older KEV entries have past dates).
    due = min(cve.kev_due_date, sla_due) if cve.kev_due_date and cve.kev_due_date >= date.today() else sla_due
    products = sorted({_pretty_product(p.vendor, p.product) for p in cve.products if p.vulnerable}
                      or {_pretty_product(p.vendor, p.product) for p in cve.products})
    remediation = cve.kev_required_action or "Apply the vendor security update referenced below to all affected assets."
    if cve.patch_refs:
        remediation += "\n\nVendor references:\n" + "\n".join(cve.patch_refs[:5])
    adv = Advisory(
        advisory_id=allocate_advisory_id(db), cve_id=cve.cve_id, template_version_id=tv.id, status=DRAFT,
        severity=severity, title=cve.title, summary=cve.description, affected_products=", ".join(products[:10]),
        remediation=remediation, sla_due_date=due, created_by=user_id, subject="", vuln_type=vuln_type(cve),
        owner_actions=DEFAULT_OWNER_ACTIONS, support_actions=DEFAULT_SUPPORT_ACTIONS,
        sources=[AdvisorySourceStatus(source=s, integrated=False, shown=True, detection_method=m)
                 for s, m in _source_specs(sources)],
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

from __future__ import annotations

from datetime import UTC, date, datetime, time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Select, and_, exists, func, or_, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, require
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.normalize import CVE_ID_RE
from exposurecatalyst.models import Cve, CveEvent, CveProduct, SavedSearch
from exposurecatalyst.security.rbac import Permission

router = APIRouter(prefix="/api", tags=["cves"])

SortKey = Literal["published_at", "-published_at", "last_modified_at", "-last_modified_at",
                  "cvss_score", "-cvss_score", "epss_score", "-epss_score", "cve_id", "-cve_id"]


class CveQuery(BaseModel):
    """Validated search criteria. Also the persisted shape of a saved search."""

    model_config = ConfigDict(extra="forbid")

    q: str | None = Field(None, max_length=200, description="CVE ID or keyword in title/description")
    vendor: str | None = Field(None, max_length=128)
    product: str | None = Field(None, max_length=256)
    severity: list[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]] = Field(default_factory=list)
    cvss_min: float | None = Field(None, ge=0, le=10)
    cvss_max: float | None = Field(None, ge=0, le=10)
    epss_min: float | None = Field(None, ge=0, le=1)
    kev: bool | None = None
    exploit: bool | None = None
    published_from: date | None = None
    published_to: date | None = None
    modified_from: date | None = None
    modified_to: date | None = None
    sort: SortKey = "-last_modified_at"


class CveSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    cve_id: str
    title: str | None
    severity: str
    cvss_score: float | None
    cvss_version: str | None
    epss_score: float | None
    epss_percentile: float | None
    kev: bool
    kev_due_date: date | None
    exploit_available: bool
    published_at: datetime | None
    last_modified_at: datetime | None
    vendors: list[str] = []


class Page(BaseModel):
    items: list[CveSummary]
    total: int
    page: int
    page_size: int


class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    vendor: str
    product: str
    cpe: str | None
    version_start_including: str | None
    version_start_excluding: str | None
    version_end_including: str | None
    version_end_excluding: str | None
    vulnerable: bool
    source: str


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    event_type: str
    occurred_at: datetime
    source: str
    detail: dict[str, Any]


class CveDetail(CveSummary):
    description: str | None
    vuln_status: str | None
    cvss_vector: str | None
    cvss_metrics: list[dict[str, Any]]
    kev_date_added: date | None
    kev_required_action: str | None
    kev_ransomware_use: str | None
    epss_date: date | None
    cwes: list[str]
    references: list[dict[str, Any]]
    exploit_refs: list[str]
    patch_refs: list[str]
    provenance: dict[str, Any]
    products: list[ProductOut]
    events: list[EventOut]


def _day_start(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=UTC)


def _day_end(d: date) -> datetime:
    return datetime.combine(d, time.max, tzinfo=UTC)


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def build_query(q: CveQuery) -> Select:
    stmt = select(Cve)
    conds = []
    if q.q:
        term = q.q.strip()
        if CVE_ID_RE.match(term.upper()):
            conds.append(Cve.cve_id == term.upper())
        else:
            conds.append(or_(Cve.cve_id.ilike(_like(term), escape="\\"),
                             Cve.title.ilike(_like(term), escape="\\"),
                             Cve.description.ilike(_like(term), escape="\\")))
    prod_conds = []
    if q.vendor:
        prod_conds.append(CveProduct.vendor.ilike(_like(q.vendor), escape="\\"))
    if q.product:
        prod_conds.append(CveProduct.product.ilike(_like(q.product), escape="\\"))
    if prod_conds:
        conds.append(exists().where(CveProduct.cve_pk == Cve.id, and_(*prod_conds)))
    if q.severity:
        conds.append(Cve.severity.in_(q.severity))
    if q.cvss_min is not None:
        conds.append(Cve.cvss_score >= q.cvss_min)
    if q.cvss_max is not None:
        conds.append(Cve.cvss_score <= q.cvss_max)
    if q.epss_min is not None:
        conds.append(Cve.epss_score >= q.epss_min)
    if q.kev is not None:
        conds.append(Cve.kev.is_(q.kev))
    if q.exploit is not None:
        conds.append(Cve.exploit_available.is_(q.exploit))
    if q.published_from:
        conds.append(Cve.published_at >= _day_start(q.published_from))
    if q.published_to:
        conds.append(Cve.published_at <= _day_end(q.published_to))
    if q.modified_from:
        conds.append(Cve.last_modified_at >= _day_start(q.modified_from))
    if q.modified_to:
        conds.append(Cve.last_modified_at <= _day_end(q.modified_to))
    if conds:
        stmt = stmt.where(and_(*conds))
    col = getattr(Cve, q.sort.lstrip("-"))  # safe: sort is a Literal whitelist
    order = col.desc() if q.sort.startswith("-") else col.asc()
    nulls = col.is_(None)  # portable "NULLS LAST" (MySQL/SQL Server lack the syntax)
    return stmt.order_by(nulls, order, Cve.id.desc())


def _summary(c: Cve) -> CveSummary:
    s = CveSummary.model_validate(c)
    s.vendors = sorted({p.vendor for p in c.products})[:5]
    return s


@router.get("/cves", response_model=Page)
def search_cves(
    q: str | None = Query(None, max_length=200),
    vendor: str | None = Query(None, max_length=128),
    product: str | None = Query(None, max_length=256),
    severity: list[str] = Query(default_factory=list),
    cvss_min: float | None = None,
    cvss_max: float | None = None,
    epss_min: float | None = None,
    kev: bool | None = None,
    exploit: bool | None = None,
    published_from: date | None = None,
    published_to: date | None = None,
    modified_from: date | None = None,
    modified_to: date | None = None,
    sort: str = "-last_modified_at",
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(25, ge=1, le=200),
    _: Principal = Depends(require(Permission.CVE_VIEW)),
    db: Session = Depends(get_db),
) -> Page:
    try:
        crit = CveQuery(q=q, vendor=vendor, product=product, severity=[s.upper() for s in severity],
                        cvss_min=cvss_min, cvss_max=cvss_max, epss_min=epss_min, kev=kev, exploit=exploit,
                        published_from=published_from, published_to=published_to,
                        modified_from=modified_from, modified_to=modified_to, sort=sort)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    stmt = build_query(crit)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[_summary(c) for c in rows], total=total, page=page, page_size=page_size)


@router.get("/cves/{cve_id}", response_model=CveDetail)
def get_cve(cve_id: str, _: Principal = Depends(require(Permission.CVE_VIEW)),
            db: Session = Depends(get_db)) -> CveDetail:
    cve_id = cve_id.upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(422, "Invalid CVE ID format (expected CVE-YYYY-NNNN)")
    cve = db.scalar(select(Cve).where(Cve.cve_id == cve_id))
    if cve is None:
        raise HTTPException(404, f"{cve_id} not found — it may not be ingested yet")
    events = db.scalars(select(CveEvent).where(CveEvent.cve_pk == cve.id).order_by(CveEvent.occurred_at.desc())
                        .limit(200)).all()
    data = {f: getattr(cve, f) for f in CveDetail.model_fields if f not in ("events", "products", "vendors")}
    data["products"] = [ProductOut.model_validate(p) for p in cve.products]
    data["events"] = [EventOut.model_validate(e) for e in events]
    data["vendors"] = sorted({p.vendor for p in cve.products})[:5]
    return CveDetail.model_validate(data)


class AssetPanel(BaseModel):
    integrations_configured: bool
    total_unique_assets: int
    sources: list[dict[str, Any]]
    message: str


@router.get("/cves/{cve_id}/assets", response_model=AssetPanel)
def cve_assets(cve_id: str, _: Principal = Depends(require(Permission.CVE_VIEW))) -> AssetPanel:
    # Populated by the connector framework in Phase 3.
    return AssetPanel(integrations_configured=False, total_unique_assets=0, sources=[],
                      message="No integrations configured. An admin can add Qualys, Tanium, Wiz, Zafran, "
                              "ArmorCode or ServiceNow CMDB under Settings → Integrations.")


# ---- Saved searches ---------------------------------------------------------------------------

class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: CveQuery

    @field_validator("name")
    @classmethod
    def strip(cls, v: str) -> str:
        return v.strip()


class SavedSearchOut(BaseModel):
    id: int
    name: str
    query: dict[str, Any]
    created_at: datetime


@router.get("/saved-searches", response_model=list[SavedSearchOut])
def list_saved(p: Principal = Depends(require(Permission.CVE_VIEW)), db: Session = Depends(get_db)):
    rows = db.scalars(select(SavedSearch).where(SavedSearch.user_id == p.user.id).order_by(SavedSearch.name))
    return [SavedSearchOut(id=r.id, name=r.name, query=r.query, created_at=r.created_at) for r in rows]


@router.post("/saved-searches", response_model=SavedSearchOut, status_code=201)
def create_saved(body: SavedSearchIn, request: Request, p: Principal = Depends(require(Permission.CVE_VIEW)),
                 db: Session = Depends(get_db)):
    if db.scalar(select(func.count()).where(SavedSearch.user_id == p.user.id)) >= 50:
        raise HTTPException(409, "Saved search limit (50) reached")
    if db.scalar(select(SavedSearch).where(SavedSearch.user_id == p.user.id, SavedSearch.name == body.name)):
        raise HTTPException(409, "A saved search with that name already exists")
    row = SavedSearch(user_id=p.user.id, name=body.name, query=body.query.model_dump(mode="json", exclude_none=True))
    db.add(row)
    db.commit()
    return SavedSearchOut(id=row.id, name=row.name, query=row.query, created_at=row.created_at)


@router.delete("/saved-searches/{search_id}", status_code=204)
def delete_saved(search_id: int, p: Principal = Depends(require(Permission.CVE_VIEW)),
                 db: Session = Depends(get_db)) -> None:
    row = db.get(SavedSearch, search_id)
    if row is None or row.user_id != p.user.id:  # no cross-user access (IDOR)
        raise HTTPException(404, "Not found")
    db.delete(row)
    db.commit()


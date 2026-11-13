"""Tab 3 — Security News, and Settings → News feeds."""

from __future__ import annotations

from datetime import date, datetime, time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import UTC
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.normalize import CVE_ID_RE
from exposurecatalyst.models import NewsFeed, NewsItem
from exposurecatalyst.news.ingest import TAGS
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P
from exposurecatalyst.security.ssrf import UnsafeURLError, validate_outbound_url

router = APIRouter(prefix="/api/news", tags=["news"])


class StoryOut(BaseModel):
    id: int
    title: str
    url: str
    source: str
    published_at: datetime
    summary: str | None
    cve_ids: list[str]
    tags: list[str]
    also: list[dict[str, Any]]


class NewsPage(BaseModel):
    items: list[StoryOut]
    total: int
    page: int
    page_size: int
    tags: list[str]
    sources: list[dict[str, Any]]


def _like(v: str) -> str:
    return "%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("", response_model=NewsPage)
def list_news(
    q: str | None = Query(None, max_length=200),
    source: list[int] = Query(default_factory=list),
    tag: str | None = Query(None, max_length=32),
    cve: str | None = Query(None, max_length=32),
    date_from: date | None = None,
    date_to: date | None = None,
    page: int = Query(1, ge=1, le=1000),
    page_size: int = Query(25, ge=1, le=100),
    _: Principal = Depends(require(P.NEWS_VIEW)),
    db: Session = Depends(get_db),
) -> NewsPage:
    return query_news(
        db, q=q, source=source, tag=tag, cve=cve, date_from=date_from, date_to=date_to, page=page, page_size=page_size
    )


def query_news(
    db: Session, *, q=None, source=(), tag=None, cve=None, date_from=None, date_to=None, page=1, page_size=25
) -> NewsPage:
    feeds = {f.id: f for f in db.scalars(select(NewsFeed))}
    stmt = select(NewsItem)
    if q:
        stmt = stmt.where(
            or_(NewsItem.title.ilike(_like(q), escape="\\"), NewsItem.summary.ilike(_like(q), escape="\\"))
        )
    if source:
        stmt = stmt.where(NewsItem.feed_id.in_(source))
    if date_from:
        stmt = stmt.where(NewsItem.published_at >= datetime.combine(date_from, time.min, tzinfo=UTC))
    if date_to:
        stmt = stmt.where(NewsItem.published_at <= datetime.combine(date_to, time.max, tzinfo=UTC))
    rows = list(db.scalars(stmt.order_by(NewsItem.published_at.desc()).limit(5000)))
    # JSON array filters are applied in Python for portability across all supported databases.
    if tag:
        rows = [r for r in rows if tag in (r.tags or [])]
    if cve:
        if not CVE_ID_RE.match(cve.upper()):
            raise HTTPException(422, "Invalid CVE ID")
        rows = [r for r in rows if cve.upper() in (r.cve_ids or [])]
    clusters: dict[int, list[NewsItem]] = {}
    order: list[int] = []
    for r in rows:
        cid = r.cluster_id or r.id
        if cid not in clusters:
            order.append(cid)
        clusters.setdefault(cid, []).append(r)
    total = len(order)
    out = []
    for cid in order[(page - 1) * page_size : page * page_size]:
        group = clusters[cid]
        lead = min(group, key=lambda x: x.published_at)  # earliest report leads the story
        out.append(
            StoryOut(
                id=lead.id,
                title=lead.title,
                url=lead.url,
                source=feeds[lead.feed_id].name if lead.feed_id in feeds else "?",
                published_at=lead.published_at,
                summary=lead.summary,
                cve_ids=sorted({c for g in group for c in (g.cve_ids or [])}),
                tags=sorted({t for g in group for t in (g.tags or [])}),
                also=[
                    {"source": feeds[g.feed_id].name if g.feed_id in feeds else "?", "url": g.url, "title": g.title}
                    for g in group
                    if g.id != lead.id
                ],
            )
        )
    return NewsPage(
        items=out,
        total=total,
        page=page,
        page_size=page_size,
        tags=sorted(TAGS),
        sources=[{"id": f.id, "name": f.name} for f in sorted(feeds.values(), key=lambda f: f.name) if f.enabled],
    )


@router.get("/by-cve/{cve_id}", response_model=list[StoryOut])
def news_for_cve(cve_id: str, _: Principal = Depends(require(P.NEWS_VIEW)), db: Session = Depends(get_db)):
    return query_news(db, cve=cve_id, page_size=20).items


# ---- Settings → News feeds --------------------------------------------------------------------


class FeedIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    url: str = Field(min_length=10, max_length=1000)
    category: str = Field("news", pattern="^(government|news|vendor-intel)$")
    enabled: bool = True


class FeedOut(BaseModel):
    id: int
    name: str
    url: str
    category: str
    enabled: bool
    is_default: bool
    status: str
    last_fetched_at: datetime | None
    last_error: str | None
    items_last_run: int
    items_total: int


def _feed_out(db: Session, f: NewsFeed) -> FeedOut:
    n = db.scalar(select(func.count()).where(NewsItem.feed_id == f.id)) or 0
    return FeedOut(
        **{
            k: getattr(f, k)
            for k in (
                "id",
                "name",
                "url",
                "category",
                "enabled",
                "is_default",
                "status",
                "last_fetched_at",
                "last_error",
                "items_last_run",
            )
        },
        items_total=n,
    )


def _check_url(url: str, settings: Settings) -> str:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    try:
        return validate_outbound_url(url, allowlist=[host], allow_private=False, resolve_dns=settings.ssrf_resolve_dns)
    except UnsafeURLError as exc:
        raise HTTPException(422, f"Feed URL rejected: {exc}") from exc


@router.get("/feeds", response_model=list[FeedOut])
def list_feeds(_: Principal = Depends(require(P.NEWS_MANAGE)), db: Session = Depends(get_db)):
    return [_feed_out(db, f) for f in db.scalars(select(NewsFeed).order_by(NewsFeed.name))]


@router.post("/feeds", response_model=FeedOut, status_code=201)
def add_feed(
    body: FeedIn,
    request: Request,
    p: Principal = Depends(require(P.NEWS_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> FeedOut:
    url = _check_url(body.url.strip(), settings)
    if db.scalar(select(NewsFeed).where(or_(func.lower(NewsFeed.name) == body.name.lower(), NewsFeed.url == url))):
        raise HTTPException(409, "A feed with that name or URL exists")
    f = NewsFeed(name=body.name.strip(), url=url, category=body.category, enabled=body.enabled)
    db.add(f)
    db.flush()
    audit.record(
        db,
        "news.feed_added",
        actor=p.user,
        request=request,
        target_type="news_feed",
        target_id=f.id,
        details={"name": f.name, "url": f.url},
    )
    db.commit()
    return _feed_out(db, f)


class FeedPatch(BaseModel):
    enabled: bool | None = None
    name: str | None = Field(None, min_length=2, max_length=100)


@router.patch("/feeds/{feed_id}", response_model=FeedOut)
def update_feed(
    feed_id: int,
    body: FeedPatch,
    request: Request,
    p: Principal = Depends(require(P.NEWS_MANAGE)),
    db: Session = Depends(get_db),
) -> FeedOut:
    f = db.get(NewsFeed, feed_id)
    if f is None:
        raise HTTPException(404, "Feed not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(f, k, v)
    audit.record(
        db,
        "news.feed_updated",
        actor=p.user,
        request=request,
        target_type="news_feed",
        target_id=f.id,
        details=body.model_dump(exclude_unset=True),
    )
    db.commit()
    return _feed_out(db, f)


@router.delete("/feeds/{feed_id}", status_code=204)
def delete_feed(
    feed_id: int, request: Request, p: Principal = Depends(require(P.NEWS_MANAGE)), db: Session = Depends(get_db)
) -> None:
    f = db.get(NewsFeed, feed_id)
    if f is None:
        raise HTTPException(404, "Feed not found")
    audit.record(
        db,
        "news.feed_deleted",
        actor=p.user,
        request=request,
        target_type="news_feed",
        target_id=f.id,
        details={"name": f.name},
    )
    db.delete(f)
    db.commit()

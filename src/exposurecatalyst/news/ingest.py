"""Security news: RSS 2.0 / Atom ingestion, de-duplication, CVE extraction, tagging.

Copyright: only headline, source, date, a short excerpt (≤ 300 chars, HTML stripped) and the link are
stored and shown — never the full article.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog
from defusedxml import ElementTree as ET  # noqa: N817 - XXE / entity-expansion safe
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc
from exposurecatalyst.ingestion.base import RunResult
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.models import NewsFeed, NewsItem, SourceState

log = structlog.get_logger(__name__)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
WORD_RE = re.compile(r"[a-z0-9]+")
TRACKING = re.compile(r"^(utm_|fbclid|gclid|mc_cid|mc_eid|ref$|cmpid|source$)", re.IGNORECASE)
SUMMARY_LIMIT = 300
SIMILARITY = 0.6
STOP = {
    "the",
    "a",
    "an",
    "of",
    "to",
    "in",
    "for",
    "and",
    "on",
    "with",
    "by",
    "is",
    "are",
    "as",
    "at",
    "from",
    "new",
    "after",
    "via",
    "its",
    "it",
    "be",
    "has",
    "have",
    "how",
    "what",
    "why",
}
TAGS = {
    "ransomware": ("ransomware", "lockbit", "blackcat", "alphv", "akira", "clop", "ransom"),
    "zero-day": ("zero-day", "zero day", "0-day", "0day", "actively exploited", "exploited in the wild"),
    "vulnerability": ("vulnerability", "cve-", "patch", "flaw", "security update", "advisory"),
    "data-breach": ("breach", "leak", "exposed data", "stolen data", "data theft"),
    "phishing": ("phishing", "credential harvesting", "smishing", "vishing"),
    "malware": ("malware", "trojan", "botnet", "stealer", "backdoor", "rootkit", "loader"),
    "apt": ("apt", "nation-state", "state-sponsored", "threat actor", "espionage"),
    "supply-chain": ("supply chain", "supply-chain", "npm", "pypi", "dependency"),
    "cloud": ("aws", "azure", "gcp", "kubernetes", "cloud"),
    "ics": ("ics", "scada", "ot ", "industrial control"),
}

DEFAULT_FEEDS = [
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "government"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("SecurityWeek", "https://www.securityweek.com/feed/", "news"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news"),
    ("The Record", "https://therecord.media/feed/", "news"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "news"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml", "news"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "vendor-intel"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/", "vendor-intel"),
    (
        "Google Threat Intelligence (Mandiant)",
        "https://cloud.google.com/blog/topics/threat-intelligence/rss/",
        "vendor-intel",
    ),
    (
        "Microsoft Threat Intelligence",
        "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
        "vendor-intel",
    ),
    ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed/", "vendor-intel"),
]


def seed_feeds(db: Session) -> None:
    existing = set(db.scalars(select(NewsFeed.url)))
    for name, url, cat in DEFAULT_FEEDS:
        if url not in existing and not db.scalar(select(NewsFeed).where(NewsFeed.name == name)):
            db.add(NewsFeed(name=name, url=url, category=cat, enabled=True, is_default=True))
    db.flush()


@dataclass
class Entry:
    title: str
    url: str
    summary: str
    published: datetime


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(el, *names: str) -> str | None:
    for child in el:
        if _local(child.tag) in names:
            return "".join(child.itertext()).strip() or child.attrib.get("href")
    return None


def _atom_link(el) -> str | None:
    best = None
    for child in el:
        if _local(child.tag) == "link":
            rel = child.attrib.get("rel", "alternate")
            if rel == "alternate" and child.attrib.get("href"):
                return child.attrib["href"]
            best = best or child.attrib.get("href")
    return best


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def clean_text(value: str | None, limit: int) -> str:
    if not value:
        return ""
    text = html.unescape(TAG_RE.sub(" ", value))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def parse_feed(data: bytes, now: datetime) -> list[Entry]:
    root = ET.fromstring(data)
    items = [el for el in root.iter() if _local(el.tag) in ("item", "entry")]
    out = []
    for el in items:
        title = clean_text(_child_text(el, "title"), 500)
        link = (_atom_link(el) if _local(el.tag) == "entry" else None) or _child_text(el, "link", "guid")
        if not title or not link or not link.lower().startswith(("http://", "https://")):
            continue
        summary = clean_text(_child_text(el, "description", "summary", "content", "encoded"), SUMMARY_LIMIT)
        published = _date(_child_text(el, "pubdate", "published", "updated", "date")) or now
        out.append(Entry(title=title, url=link.strip()[:1000], summary=summary, published=min(published, now)))
    return out


def canonical_url(url: str) -> str:
    p = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(p.query) if not TRACKING.match(k)])
    path = p.path.rstrip("/") or "/"
    return urlunsplit(("https", p.netloc.lower().removeprefix("www."), path, query, ""))[:1000]


def title_key(title: str) -> str:
    return " ".join(sorted({w for w in WORD_RE.findall(title.lower()) if w not in STOP and len(w) > 2}))[:500]


def similar(a: str, b: str) -> bool:
    sa, sb = set(a.split()), set(b.split())
    if not sa or not sb:
        return False
    return len(sa & sb) / len(sa | sb) >= SIMILARITY


def tags_for(text: str) -> list[str]:
    low = f" {text.lower()} "
    return sorted(t for t, words in TAGS.items() if any(w in low for w in words))


class NewsSource:
    name = "news"

    def __init__(self, settings: Settings, transport=None, sleep=None):
        self.settings = settings
        self.transport, self.sleep = transport, sleep

    def close(self) -> None:
        pass

    def _client(self, feed: NewsFeed) -> SourceClient:
        host = (urlsplit(feed.url).hostname or "").lower()
        kw = {"sleep": self.sleep} if self.sleep else {}
        return SourceClient(
            f"news:{feed.name}",
            self.settings,
            rate=2,
            per=1.0,
            transport=self.transport,
            allowlist=[host],
            headers={"Accept": "application/rss+xml, application/atom+xml, text/xml"},
            **kw,
        )

    def run(self, db: Session, state: SourceState, now: datetime) -> RunResult:
        result = RunResult(detail={"feeds": 0, "failed": 0, "new": 0, "clustered": 0})
        recent = list(
            db.execute(
                select(NewsItem.id, NewsItem.title_key, NewsItem.cluster_id).where(
                    NewsItem.published_at > now - timedelta(days=3)
                )
            ).all()
        )
        for feed in db.scalars(select(NewsFeed).where(NewsFeed.enabled.is_(True)).order_by(NewsFeed.id)):
            client = self._client(feed)
            try:
                resp = client.get(
                    feed.url, headers={"If-None-Match": feed.etag} if feed.etag else None, ok_statuses=(200, 304)
                )
                entries = [] if resp.status_code == 304 else parse_feed(resp.content, now)
                feed.etag = resp.headers.get("etag") or feed.etag
                new = 0
                for e in sorted(entries, key=lambda x: x.published, reverse=True)[
                    : self.settings.news_max_items_per_feed
                ]:
                    canon = canonical_url(e.url)
                    if db.scalar(select(NewsItem.id).where(NewsItem.canonical_url == canon)):
                        continue
                    key = title_key(e.title)
                    text = f"{e.title} {e.summary}"
                    item = NewsItem(
                        feed_id=feed.id,
                        url=e.url,
                        canonical_url=canon,
                        title=e.title,
                        title_key=key,
                        summary=e.summary or None,
                        published_at=e.published,
                        fetched_at=now,
                        cve_ids=sorted({c.upper() for c in CVE_RE.findall(text)})[:50],
                        tags=tags_for(text),
                    )
                    db.add(item)
                    db.flush()
                    match = next((r for r in recent if similar(r.title_key, key)), None)
                    item.cluster_id = (match.cluster_id or match.id) if match else item.id
                    result.detail["clustered"] += bool(match)
                    recent.append(type("R", (), {"id": item.id, "title_key": key, "cluster_id": item.cluster_id})())
                    new += 1
                feed.status, feed.last_error, feed.items_last_run = "ok", None, new
                result.detail["new"] += new
                result.records += new
            except Exception as exc:  # noqa: BLE001 - one broken feed never blocks the others
                feed.status, feed.last_error = "error", f"{type(exc).__name__}: {str(exc)[:300]}"
                result.detail["failed"] += 1
                log.warning("news_feed_failed", feed=feed.name, error=feed.last_error)
            finally:
                client.close()
                feed.last_fetched_at = now
                result.detail["feeds"] += 1
                db.commit()
        db.execute(
            delete(NewsItem).where(NewsItem.published_at < now - timedelta(days=self.settings.news_retention_days))
        )
        db.commit()
        if result.detail["feeds"] and result.detail["failed"] == result.detail["feeds"]:
            raise RuntimeError("all news feeds failed")
        return result


def iter_clusters(items: list[NewsItem]) -> Iterator[list[NewsItem]]:
    groups: dict[int, list[NewsItem]] = {}
    for i in items:
        groups.setdefault(i.cluster_id or i.id, []).append(i)
    for g in groups.values():
        yield sorted(g, key=lambda x: as_utc(x.published_at))

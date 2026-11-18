"""Generic subscription engine: auth, pagination, JSONPath field mapping, RSS and TAXII 2.1 / STIX 2.1.

Security: every URL (base, token endpoint, pagination links) must be https and on the subscription's own host,
the preset's vendor hosts or EXCAT_EGRESS_ALLOWLIST, and must not resolve to private / metadata addresses
(EXCAT_SSRF_ALLOW_PRIVATE_NETWORKS opts in for internal TAXII servers). Redirects are not followed; responses are
size-capped and parsed as untrusted data.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from exposurecatalyst.config import Settings
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.news.ingest import CVE_RE, clean_text, parse_feed
from exposurecatalyst.security.ssrf import UnsafeURLError, host_matches, validate_outbound_url
from exposurecatalyst.subscriptions import jsonpath
from exposurecatalyst.subscriptions.presets import PRESETS

MAX_PAGES = 50
MAX_ITEMS = 5000
PREVIEW_ITEMS = 10
DEFAULT_LIMIT = 100
TEXT_LIMIT = 8000
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
TLP = ("CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED")
EXPLOITED_TRUE = {
    "true",
    "yes",
    "1",
    "active",
    "wild",
    "in the wild",
    "exploited",
    "confirmed",
    "weaponized",
    "available",
    "widespread",
}
EXPLOITED_FALSE = {"false", "no", "0", "none", "not observed", "unproven", "not exploited"}


class SourceError(RuntimeError):
    """User-actionable failure (auth, URL, mapping, quota)."""


@dataclass
class Record:
    kind: str  # cve | news
    external_id: str
    title: str
    cve_ids: list[str] = field(default_factory=list)
    summary: str | None = None
    description: str | None = None
    severity: str | None = None
    exploited: bool | None = None
    references: list[str] = field(default_factory=list)
    url: str | None = None
    published_at: datetime | None = None
    tags: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["published_at"] = self.published_at.isoformat() if self.published_at else None
        return d


@dataclass
class FetchResult:
    records: list[Record]
    calls: int
    raw_sample: Any = None
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


# ---- value coercion --------------------------------------------------------------------------------------


def to_dt(v: Any) -> datetime | None:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{9,14}", v.strip())):
        n = float(v)
        if n > 1e11:
            n /= 1000
        try:
            return datetime.fromtimestamp(n, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except ValueError:
        pass
    from email.utils import parsedate_to_datetime

    try:
        d = parsedate_to_datetime(s)
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


def to_severity(v: Any) -> str | None:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)) or re.fullmatch(r"\d+(\.\d+)?", str(v).strip()):
        n = float(v)
        if n > 10:  # 0-100 risk scores
            n /= 10
        return "CRITICAL" if n >= 9 else "HIGH" if n >= 7 else "MEDIUM" if n >= 4 else "LOW"
    s = str(v).strip().upper()
    if "CRIT" in s or s == "VERY CRITICAL":
        return "CRITICAL"
    for sev in SEVERITIES:
        if sev in s:
            return sev
    return None


def to_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if v in (None, ""):
        return None
    if isinstance(v, dict):  # e.g. {"wild": true}
        return any(to_bool(x) for x in v.values()) or None
    s = str(v).strip().lower()
    if s in EXPLOITED_TRUE:
        return True
    if s in EXPLOITED_FALSE:
        return False
    return None


def _list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _text(v: Any, limit: int = TEXT_LIMIT) -> str | None:
    if v in (None, "", []):
        return None
    if isinstance(v, list):
        v = "; ".join(str(x) for x in v if x not in (None, ""))
    if isinstance(v, dict):
        v = json.dumps(v)[:limit]
    return clean_text(str(v), limit) or None


def map_record(raw: Any, mapping: dict[str, str], target: str) -> Record | None:
    """Apply a JSONPath field map to one raw record. Values starting with '=' are constants."""

    def get(key: str, many: bool = False) -> Any:
        path = mapping.get(key)
        if not path:
            return [] if many else None
        if path.startswith("="):
            return path[1:]
        return jsonpath.find(raw, path) if many else jsonpath.first(raw, path)

    title = _text(get("title"), 500)
    cves: list[str] = []
    for v in get("cve_id", many=True):
        for item in _list(v):
            cves += [m.upper() for m in CVE_RE.findall(str(item))]
    if not cves and target == "cve":
        for blob in (title, _text(get("description")), _text(get("summary"))):
            cves += [m.upper() for m in CVE_RE.findall(blob or "")]
    cves = list(dict.fromkeys(cves))[:50]
    ext = get("external_id")
    external_id = str(ext if ext not in (None, "") else (cves[0] if cves else title or ""))[:255]
    if not external_id or not (title or cves):
        return None
    if target == "cve" and not cves:
        return None
    refs = [str(r)[:1000] for r in get("references", many=True) for r in _list(r) if str(r).startswith("http")][:20]
    url = get("url")
    tags = [str(t)[:64] for t in get("tags", many=True) for t in _list(t) if t not in (None, "")][:20]
    news_cves = (
        cves or list(dict.fromkeys(m.upper() for m in CVE_RE.findall(f"{title} {_text(get('summary')) or ''}")))[:20]
    )
    return Record(
        kind=target,
        external_id=external_id,
        title=title or cves[0],
        cve_ids=cves or news_cves,
        summary=_text(get("summary"), 1000),
        description=_text(get("description")),
        severity=to_severity(get("severity")),
        exploited=to_bool(get("exploited")),
        references=refs,
        url=str(url)[:1000] if isinstance(url, str) and url.startswith("http") else None,
        published_at=to_dt(get("published")),
        tags=tags,
    )


# ---- STIX 2.1 --------------------------------------------------------------------------------------------


def stix_records(objects: list[dict[str, Any]]) -> tuple[list[Record], int]:
    out, skipped = [], 0
    for o in objects:
        if not isinstance(o, dict):
            skipped += 1
            continue
        t = o.get("type")
        refs = [r for r in o.get("external_references") or [] if isinstance(r, dict)]
        if t == "vulnerability":
            cves = [
                str(r.get("external_id")).upper()
                for r in refs
                if str(r.get("source_name", "")).lower() == "cve" and r.get("external_id")
            ]
            cves += [m.upper() for m in CVE_RE.findall(str(o.get("name", "")))]
            cves = list(dict.fromkeys(c for c in cves if CVE_RE.fullmatch(c)))
            if not cves:
                skipped += 1
                continue
            out.append(
                Record(
                    kind="cve",
                    external_id=str(o.get("id"))[:255],
                    title=str(o.get("name") or cves[0])[:500],
                    cve_ids=cves,
                    description=_text(o.get("description")),
                    references=[str(r["url"])[:1000] for r in refs if str(r.get("url", "")).startswith("http")],
                    published_at=to_dt(o.get("modified") or o.get("created")),
                    tags=[str(x)[:64] for x in o.get("labels") or []][:20],
                )
            )
        elif t == "report":
            text = f"{o.get('name', '')} {o.get('description', '')}"
            url = next((r.get("url") for r in refs if str(r.get("url", "")).startswith("http")), None)
            out.append(
                Record(
                    kind="news",
                    external_id=str(o.get("id"))[:255],
                    title=_text(o.get("name"), 500) or "Report",
                    summary=_text(o.get("description"), 1000),
                    cve_ids=list(dict.fromkeys(m.upper() for m in CVE_RE.findall(text)))[:20],
                    url=url,
                    published_at=to_dt(o.get("published") or o.get("modified")),
                    tags=[str(x)[:64] for x in o.get("labels") or []][:20],
                )
            )
        else:
            skipped += 1
    return out, skipped


# ---- URL safety ------------------------------------------------------------------------------------------


def allowed_hosts(preset: str, base_url: str | None, settings: Settings) -> list[str]:
    hosts = list(PRESETS.get(preset, {}).get("hosts") or []) + list(PRESETS.get(preset, {}).get("token_hosts") or [])
    if base_url:
        hosts.append((urlsplit(base_url).hostname or "").lower())
    return [h for h in hosts if h] + settings.egress_allowlist_list


def check_url(url: str, hosts: list[str], settings: Settings) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise SourceError(f"URL must use https: {url[:80]}")
    if not host_matches((parts.hostname or "").lower(), hosts):
        raise SourceError(f"host '{parts.hostname}' is not allowed for this subscription")
    try:
        validate_outbound_url(
            url,
            allowlist=hosts,
            allow_private=settings.ssrf_allow_private_networks,
            resolve_dns=settings.ssrf_resolve_dns,
        )
    except UnsafeURLError as exc:
        raise SourceError(str(exc)) from exc
    return url


def validate_base_url(preset: str, url: str, settings: Settings) -> str:
    url = url.strip()
    p = PRESETS.get(preset, {})
    vendor_hosts = list(p.get("hosts") or [])
    host = (urlsplit(url).hostname or "").lower()
    if vendor_hosts and not host_matches(host, vendor_hosts + settings.egress_allowlist_list):
        raise SourceError(
            f"host '{host}' is not a {p.get('vendor')} host ({', '.join(vendor_hosts)}); add it to "
            "EXCAT_EGRESS_ALLOWLIST for a regional / private instance"
        )
    if urlsplit(url).fragment:
        raise SourceError("base URL must not contain a fragment")
    return check_url(url, allowed_hosts(preset, url, settings), settings)


# ---- client ----------------------------------------------------------------------------------------------


def _fmt(template: str, values: dict[str, Any]) -> str:
    return re.sub(r"\{([a-z_]+)\}", lambda m: str(values.get(m.group(1), m.group(0))), template)


class Source:
    def __init__(
        self,
        preset: str,
        source_type: str,
        base_url: str | None,
        config: dict[str, Any],
        secrets: dict[str, str],
        settings: Settings,
        *,
        since: datetime,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ):
        self.preset, self.source_type, self.config, self.secrets, self.settings = (
            preset,
            source_type,
            config,
            secrets,
            settings,
        )
        self.base_url = (base_url or "").rstrip("/")
        self.hosts = allowed_hosts(preset, base_url, settings)
        rate = max(1, int(config.get("rate_per_minute") or 30))
        self.client = SourceClient(
            f"subscription:{preset}",
            settings,
            rate=rate,
            per=60.0,
            transport=transport,
            allowlist=self.hosts,
            timeout=settings.connector_timeout_seconds,
            **({"sleep": sleep} if sleep else {}),
        )
        self.calls = 0
        self._token: str | None = None
        self.values = {
            **{k: v for k, v in config.items() if isinstance(v, (str, int, float))},
            "base_url": self.base_url,
            "limit": int(config.get("page_size") or DEFAULT_LIMIT),
            "since_iso": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "since_date": since.strftime("%Y-%m-%d"),
            "since_epoch": int(since.timestamp()),
            "since_epoch_ms": int(since.timestamp() * 1000),
        }

    def close(self) -> None:
        self.client.close()

    # -- auth --
    def _auth(self) -> tuple[dict[str, str], dict[str, str], tuple[str, str] | None]:
        a = self.config.get("auth") or {"type": "none"}
        kind = a.get("type", "none")
        headers = {k: _fmt(str(v), self.values) for k, v in (self.config.get("headers") or {}).items()}
        params: dict[str, str] = {}
        basic = None
        if kind == "api_key_header":
            headers[a.get("header") or "X-API-Key"] = f"{a.get('prefix') or ''}{self.secrets.get('api_key', '')}"
        elif kind == "api_key_query":
            params[a.get("param") or "api_key"] = self.secrets.get("api_key", "")
        elif kind == "bearer":
            headers["Authorization"] = f"Bearer {self.secrets.get('token', '')}"
        elif kind == "basic":
            basic = (self.secrets.get("username", ""), self.secrets.get("password", ""))
        elif kind == "oauth2_cc":
            headers["Authorization"] = f"Bearer {self._oauth_token(a)}"
        elif kind == "custom_headers":
            try:
                custom = json.loads(self.secrets.get("custom_headers") or "{}")
            except ValueError as exc:
                raise SourceError("custom headers must be a JSON object") from exc
            headers.update({str(k): str(v) for k, v in custom.items()})
        elif kind != "none":
            raise SourceError(f"unsupported auth type {kind}")
        return headers, params, basic

    def _oauth_token(self, a: dict[str, Any]) -> str:
        if self._token:
            return self._token
        url = _fmt(a.get("token_url") or "", self.values)
        check_url(url, self.hosts, self.settings)
        cid, secret = self.secrets.get("client_id", ""), self.secrets.get("client_secret", "")
        data = {"grant_type": a.get("grant_type") or "client_credentials"}
        if a.get("scope"):
            data["scope"] = a["scope"]
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        if a.get("client_auth") == "basic":
            headers["Authorization"] = "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()
        else:
            data |= {"client_id": cid, "client_secret": secret}
        resp = self.client.request("POST", url, data=data, headers=headers, ok_statuses=(200, 201))
        self.calls += 1
        try:
            token = resp.json().get("access_token") or resp.json().get("dmaToken")
        except ValueError:
            token = None
        if not token:
            raise SourceError("the token endpoint did not return an access token — check the client credentials")
        self._token = token
        return token

    def _get(self, url: str, params: dict[str, Any] | None = None, accept: str = "application/json") -> httpx.Response:
        check_url(url, self.hosts, self.settings)
        headers, auth_params, basic = self._auth()
        headers.setdefault("Accept", accept)
        self.calls += 1
        return self.client.request(
            "GET", url, params={**auth_params, **(params or {})} or None, headers=headers, auth=basic
        )

    def _json(self, resp: httpx.Response) -> Any:
        if len(resp.content) > 20_000_000:
            raise SourceError("response too large")
        try:
            return resp.json()
        except ValueError as exc:
            raise SourceError(f"the API returned non-JSON ({resp.headers.get('content-type', '?')})") from exc

    # -- fetch --
    def fetch(self, *, preview: bool = False) -> FetchResult:
        if self.source_type == "rss":
            return self._fetch_rss(preview)
        if self.source_type == "taxii":
            return self._fetch_taxii(preview)
        if self.source_type == "rest":
            records, sample, skipped = [], None, 0
            endpoints = self.config.get("endpoints") or []
            if not endpoints:
                raise SourceError("no endpoints configured")
            for ep in endpoints:
                r = self._fetch_endpoint(ep, preview)
                records += r.records
                skipped += r.skipped
                sample = sample if sample is not None else r.raw_sample
                if preview and len(records) >= PREVIEW_ITEMS:
                    break
            return FetchResult(records[:PREVIEW_ITEMS] if preview else records, self.calls, sample, skipped)
        raise SourceError("manual subscriptions are not pulled (use manual entry or import)")

    def _fetch_endpoint(self, ep: dict[str, Any], preview: bool) -> FetchResult:
        target = ep.get("target") if ep.get("target") in ("cve", "news") else "cve"
        mapping = ep.get("mapping") or {}
        params = {k: _fmt(str(v), self.values) for k, v in (ep.get("params") or {}).items()}
        url = urljoin(self.base_url + "/", _fmt(ep.get("path") or "", self.values).lstrip("/"))
        pag = ep.get("pagination") or {"type": "none"}
        ptype = pag.get("type", "none")
        page_no, offset, out, sample, skipped = int(pag.get("start") or 1), 0, [], None, 0
        if ptype == "page":
            params[pag.get("param") or "page"] = str(page_no)
        for _ in range(1 if preview else MAX_PAGES):
            resp = self._get(url, params)
            body = self._json(resp)
            rows = jsonpath.find(body, ep.get("results_path") or "$[*]")
            if sample is None and rows:
                sample = rows[0]
            for raw in rows:
                rec = map_record(raw, mapping, target)
                if rec is None:
                    skipped += 1
                else:
                    out.append(rec)
            if not rows or len(out) >= MAX_ITEMS:
                break
            if ptype == "offset":
                offset += len(rows)
                params[pag.get("param") or "offset"] = str(offset)
            elif ptype == "page":
                page_no += 1
                params[pag.get("param") or "page"] = str(page_no)
            elif ptype == "cursor":
                nxt = jsonpath.first(body, pag.get("next_path") or "$.next")
                if not nxt:
                    break
                for p in pag.get("drop_params") or []:
                    params.pop(p, None)
                params[pag.get("param") or "cursor"] = str(nxt)
            elif ptype == "next_url":
                nxt = jsonpath.first(body, pag.get("next_path") or "$.next")
                if not nxt:
                    break
                url, params = urljoin(url, str(nxt)), {}
            elif ptype == "link_header":
                nxt = resp.links.get("next", {}).get("url")
                if not nxt:
                    break
                url, params = urljoin(url, nxt), {}
            else:
                break
        return FetchResult(out, self.calls, sample, skipped)

    def _fetch_rss(self, preview: bool) -> FetchResult:
        resp = self._get(self.base_url, accept="application/rss+xml, application/atom+xml, application/xml")
        if len(resp.content) > 10_000_000:
            raise SourceError("feed too large")
        try:
            entries = parse_feed(resp.content, datetime.now(UTC))
        except Exception as exc:  # noqa: BLE001 - malformed XML from the vendor
            raise SourceError(f"could not parse the feed: {type(exc).__name__}") from exc
        out = [
            Record(
                kind="news",
                external_id=e.url[:255],
                title=e.title,
                summary=e.summary or None,
                url=e.url,
                published_at=e.published,
                cve_ids=list(dict.fromkeys(m.upper() for m in CVE_RE.findall(f"{e.title} {e.summary}")))[:20],
            )
            for e in entries
        ]
        return FetchResult(
            out[:PREVIEW_ITEMS] if preview else out,
            self.calls,
            {"title": entries[0].title, "url": entries[0].url} if entries else None,
        )

    def _fetch_taxii(self, preview: bool) -> FetchResult:
        coll = str(self.config.get("collection_id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", coll):
            raise SourceError("TAXII collection ID is required")
        url = urljoin(self.base_url + "/", f"collections/{coll}/objects/")
        params: dict[str, Any] = {"added_after": self.values["since_iso"], "limit": str(self.values["limit"])}
        out, skipped, sample = [], 0, None
        for _ in range(1 if preview else MAX_PAGES):
            body = self._json(self._get(url, params, accept="application/taxii+json;version=2.1"))
            objects = body.get("objects") or [] if isinstance(body, dict) else []
            sample = sample or (objects[0] if objects else None)
            recs, sk = stix_records(objects)
            out += recs
            skipped += sk
            if not body.get("more") or not body.get("next") or len(out) >= MAX_ITEMS:
                break
            params = {**params, "next": str(body["next"])}
        return FetchResult(out[:PREVIEW_ITEMS] if preview else out, self.calls, sample, skipped)


def since_for(state: dict[str, Any], config: dict[str, Any], now: datetime) -> datetime:
    """Incremental window: from the newest item already stored (minus 1 h overlap), else `initial_days` back."""
    last = to_dt(state.get("last_published")) if state.get("last_published") else None
    return last - timedelta(hours=1) if last else now - timedelta(days=int(config.get("initial_days") or 7))

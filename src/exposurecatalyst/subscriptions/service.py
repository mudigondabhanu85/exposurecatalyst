"""Subscriptions: configuration, sync, manual intel / import, licence metadata and redistribution enforcement.

Redistribution (per source, enforced here — the advisory renderer and the AI context builder only ever call the
``email_intel`` / ``ai_intel_text`` views below):
* ``email``: "full" (title, summary, description, references) | "summary" (title + summary) | "none"
* ``ai``: whether the source's content may be sent to external AI providers (default False)
* ``default_tlp``: TLP for pulled items. TLP:RED never leaves the platform (no email, no AI) and is visible only to
  users with intel:manage.
Free sources (NVD, KEV, EPSS, RSS news feeds) are not subscriptions and behave exactly as before.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import AppSetting, IntelItem, IntelSubscription
from exposurecatalyst.news.ingest import CVE_RE
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.subscriptions import engine
from exposurecatalyst.subscriptions.presets import PRESETS

log = structlog.get_logger(__name__)
EMAIL_MODES = ("full", "summary", "none")
DEFAULT_REDISTRIBUTION = {"email": "summary", "ai": False, "default_tlp": "AMBER"}
LICENSE_FIELDS = ("contract_owner", "license_tier", "seats", "api_quota", "quota_period", "start_date",
                  "renewal_date", "cost_center", "notes")
RENEWAL_THRESHOLDS = (60, 30, 7)
ERROR_LOG_MAX = 20
IMPORT_MAX_ROWS = 5000
TRANSPORTS: dict[str, httpx.BaseTransport] = {}  # test hook, keyed by preset


class IntelError(ValueError):
    pass


# ---- secrets / config --------------------------------------------------------------------------------------

def load_secrets(sub: IntelSubscription) -> dict[str, str]:
    return json.loads(get_secret_box().decrypt(sub.secrets_enc)) if sub.secrets_enc else {}


def store_secrets(sub: IntelSubscription, secrets: dict[str, str]) -> None:
    clean = {k: v for k, v in secrets.items() if v}
    sub.secrets_enc = get_secret_box().encrypt(json.dumps(clean)) if clean else None


def effective_config(preset: str, config: dict[str, Any]) -> dict[str, Any]:
    """Preset defaults (auth, headers, endpoints) overlaid with the subscription's own settings."""
    p = PRESETS.get(preset, {})
    out = {"auth": p.get("auth") or {"type": "none"}, "headers": p.get("headers") or {},
           "endpoints": p.get("endpoints") or []}
    out.update({k: v for k, v in (config or {}).items() if v not in (None, "")})
    return out


def redistribution(sub: IntelSubscription) -> dict[str, Any]:
    return {**DEFAULT_REDISTRIBUTION, **(sub.redistribution or {})}


def build_source(sub: IntelSubscription, settings: Settings, *, config: dict[str, Any] | None = None,
                 secrets: dict[str, str] | None = None, now: datetime | None = None) -> engine.Source:
    cfg = effective_config(sub.preset, config if config is not None else sub.config)
    since = engine.since_for(sub.state or {}, cfg, now or utcnow())
    return engine.Source(sub.preset, sub.source_type, sub.base_url, cfg,
                         secrets if secrets is not None else load_secrets(sub), settings, since=since,
                         transport=TRANSPORTS.get(sub.preset))


# ---- usage / quota -----------------------------------------------------------------------------------------

def _period_start(now: datetime, period: str) -> str:
    if period == "day":
        return now.date().isoformat()
    if period == "year":
        return date(now.year, 1, 1).isoformat()
    return date(now.year, now.month, 1).isoformat()


def _usage(sub: IntelSubscription, now: datetime) -> dict[str, Any]:
    period = (sub.license or {}).get("quota_period") or "month"
    start = _period_start(now, period)
    u = dict(sub.usage or {})
    if u.get("period_start") != start:
        u = {"period_start": start, "api_calls": 0, "items": 0}
    return u


def quota_left(sub: IntelSubscription, now: datetime) -> int | None:
    quota = (sub.license or {}).get("api_quota")
    if not quota:
        return None
    return max(int(quota) - int(_usage(sub, now).get("api_calls", 0)), 0)


# ---- test / preview / sync ---------------------------------------------------------------------------------

def preview(sub: IntelSubscription, settings: Settings, *, config: dict[str, Any] | None = None,
            secrets: dict[str, str] | None = None) -> dict[str, Any]:
    """Fetch the first page and map it — nothing is stored (Test & preview)."""
    src = build_source(sub, settings, config=config, secrets=secrets)
    try:
        res = src.fetch(preview=True)
    finally:
        src.close()
    sample = json.dumps(res.raw_sample, default=str)[:4000] if res.raw_sample is not None else None
    return {"ok": True, "records": [r.public() for r in res.records], "skipped": res.skipped, "raw_sample": sample,
            "calls": res.calls}


def _log_error(sub: IntelSubscription, message: str, now: datetime) -> None:
    sub.error_log = ([{"at": now.isoformat(), "error": message[:500]}] + list(sub.error_log or []))[:ERROR_LOG_MAX]
    sub.status, sub.last_error = "error", message[:500]


def sync(db: Session, sub: IntelSubscription, settings: Settings, *, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    sub.last_sync_at = now
    left = quota_left(sub, now)
    if left == 0:
        _log_error(sub, "API quota for this period is used up (licence metadata) — sync skipped", now)
        db.commit()
        return {"ok": False, "error": sub.last_error}
    src = build_source(sub, settings, now=now)
    try:
        res = src.fetch()
    except Exception as exc:  # noqa: BLE001 - per-subscription isolation; message shown to admins
        u = _usage(sub, now)
        u["api_calls"] += src.calls
        sub.usage = u
        _log_error(sub, f"{type(exc).__name__}: {exc}", now)
        db.commit()
        log.warning("subscription_sync_failed", subscription=sub.name, error=sub.last_error)
        return {"ok": False, "error": sub.last_error}
    finally:
        src.close()
    tlp = redistribution(sub)["default_tlp"]
    created = updated = 0
    existing = {i.external_id: i for i in db.scalars(select(IntelItem).where(IntelItem.subscription_id == sub.id))}
    newest = engine.to_dt((sub.state or {}).get("last_published"))
    for r in res.records:
        item = existing.get(r.external_id)
        if item is not None and item.is_manual:
            continue  # never overwrite analyst-entered items
        if item is None:
            item = IntelItem(subscription_id=sub.id, external_id=r.external_id, tlp=tlp, is_manual=False,
                             created_by=f"sync:{sub.name}"[:150])
            db.add(item)
            existing[r.external_id] = item
            created += 1
        else:
            updated += 1
        item.kind, item.title, item.cve_ids = r.kind, r.title, r.cve_ids
        item.summary, item.description, item.severity = r.summary, r.description, r.severity
        item.exploited, item.references, item.url = r.exploited, r.references, r.url
        item.published_at, item.tags = r.published_at, r.tags
        if r.published_at and (newest is None or r.published_at > newest):
            newest = r.published_at
    u = _usage(sub, now)
    u["api_calls"] += res.calls
    u["items"] = int(u.get("items", 0)) + created
    sub.usage = u
    sub.state = {**(sub.state or {}), **({"last_published": newest.isoformat()} if newest else {})}
    sub.status, sub.last_error, sub.last_success_at = "ok", None, now
    db.commit()
    return {"ok": True, "created": created, "updated": updated, "skipped": res.skipped, "calls": res.calls}


def due(db: Session, now: datetime) -> list[IntelSubscription]:
    out = []
    for sub in db.scalars(select(IntelSubscription).where(IntelSubscription.enabled.is_(True))):
        if sub.source_type == "manual":
            continue
        minutes = int((sub.config or {}).get("poll_minutes") or 60)
        if sub.last_sync_at is None or as_utc(sub.last_sync_at) + timedelta(minutes=minutes) <= now:
            out.append(sub)
    return out


def tick(settings: Settings, session_factory) -> None:
    """Scheduler entry point (every 5 minutes). No-op unless features.subscriptions is on."""
    if not settings.features.subscriptions:
        return
    now = utcnow()
    with session_factory() as db:
        for sub in due(db, now):
            sync(db, sub, settings, now=now)
        renewal_reminders(db, settings, now=now)


# ---- licence renewal reminders -----------------------------------------------------------------------------

def renewal_reminders(db: Session, settings: Settings, *, now: datetime | None = None,
                      send: Callable[[Session, Settings, IntelSubscription, int], None] | None = None) -> list[str]:
    now = now or utcnow()
    key = "subscriptions.renewal_alerts"
    row = db.get(AppSetting, key)
    state = dict(row.value) if row and row.value else {}
    fired = []
    for sub in db.scalars(select(IntelSubscription)):
        renewal = (sub.license or {}).get("renewal_date")
        try:
            d = date.fromisoformat(str(renewal)) if renewal else None
        except ValueError:
            d = None
        if d is None:
            continue
        days = (d - now.date()).days
        due_t = [t for t in RENEWAL_THRESHOLDS if days <= t]
        if not due_t or days < -1:
            continue
        sent_key = f"{sub.id}:{d.isoformat()}"
        sent = set(state.get(sent_key, []))
        threshold = min(due_t)
        if threshold in sent:
            continue
        (send or _email_renewal)(db, settings, sub, days)
        state[sent_key] = sorted(sent | set(due_t))
        audit.record(db, "subscription.renewal_reminder", actor_username="system", target_type="subscription",
                     target_id=sub.id, details={"days_left": days, "threshold": threshold})
        fired.append(f"{sub.name}:{threshold}")
    if fired:
        if row is None:
            db.add(AppSetting(key=key, value=state, updated_by="system"))
        else:
            row.value = state
        db.commit()
    return fired


def _email_renewal(db: Session, settings: Settings, sub: IntelSubscription, days: int) -> None:
    from email.message import EmailMessage

    from exposurecatalyst.advisories.delivery import send
    from exposurecatalyst.api.smtp import load_config
    from exposurecatalyst.models import User
    from exposurecatalyst.security.rbac import Permission, user_permissions

    cfg = load_config(db)
    owner = (sub.license or {}).get("contract_owner") or ""
    to = sorted({u.email for u in db.scalars(select(User).where(User.is_active.is_(True)))
                 if u.email and str(Permission.INTEGRATION_MANAGE) in user_permissions(u)}
                | ({owner} if "@" in owner else set()))
    if cfg is None or not to:
        log.warning("subscription_renewal_not_emailed", subscription=sub.name, days_left=days)
        return
    msg = EmailMessage()
    msg["Subject"] = f"[ExposureCatalyst] {sub.vendor} subscription renews in {max(days, 0)} day(s)"
    msg["From"], msg["To"] = cfg.from_address, ", ".join(to)
    lic = sub.license or {}
    msg.set_content(f"Subscription: {sub.name} ({sub.vendor})\nRenewal date: {lic.get('renewal_date')}\n"
                    f"Licence tier: {lic.get('license_tier') or '-'} · seats: {lic.get('seats') or '-'} · "
                    f"cost center: {lic.get('cost_center') or '-'}\n\nReview: {settings.public_url.rstrip('/')}"
                    "/settings/integrations\n")
    send(msg, to, cfg, settings)


# ---- visibility & redistribution views ---------------------------------------------------------------------

def visible_items(db: Session, *, cve_id: str | None = None, kind: str | None = None, can_red: bool = False,
                  limit: int = 200) -> list[IntelItem]:
    q = select(IntelItem).join(IntelSubscription).order_by(IntelItem.published_at.desc().nullslast(),
                                                           IntelItem.id.desc())
    if kind:
        q = q.where(IntelItem.kind == kind)
    rows = list(db.scalars(q.limit(5000 if cve_id else limit)))
    if cve_id:
        rows = [r for r in rows if cve_id in (r.cve_ids or [])][:limit]
    return [r for r in rows if can_red or r.tlp != "RED"]


def attribution(item: IntelItem) -> str:
    sub = item.subscription
    return f"Manual — {sub.name}" if item.is_manual else f"{sub.vendor} · {sub.name}"


def email_intel(db: Session, cve_id: str) -> list[dict[str, Any]]:
    """What the advisory email may contain, per each source's licence (TLP:RED never)."""
    out = []
    for item in visible_items(db, cve_id=cve_id, can_red=False, limit=20):
        mode = redistribution(item.subscription)["email"]
        if mode == "none" or not item.subscription.enabled and not item.is_manual:
            continue
        entry = {"source": attribution(item), "title": item.title, "tlp": item.tlp, "summary": item.summary,
                 "exploited": item.exploited, "published": item.published_at.date().isoformat()
                 if item.published_at else None}
        if mode == "full":
            entry |= {"description": (item.description or "")[:1500] or None, "references": item.references[:5],
                      "url": item.url}
        out.append(entry)
    return out[:10]


def ai_intel_text(db: Session, cve_id: str) -> str:
    """Licensed intel the AI layer may see: only sources with ai=True, never TLP:RED."""
    lines = []
    for item in visible_items(db, cve_id=cve_id, can_red=False, limit=10):
        if not redistribution(item.subscription)["ai"]:
            continue
        exploited = {True: "exploited", False: "not exploited"}.get(item.exploited, "exploitation unknown")
        lines.append(f"- [{attribution(item)}] {item.title}: {item.summary or item.description or ''} "
                     f"({exploited}; severity {item.severity or '?'})"[:800])
    return "\n".join(lines)


# ---- manual entry & import ---------------------------------------------------------------------------------

def _cves(value: Any) -> list[str]:
    raw = value if isinstance(value, list) else [value] if value else []
    return list(dict.fromkeys(m.upper() for v in raw for m in CVE_RE.findall(str(v))))[:50]


def normalize_manual(data: dict[str, Any], *, default_tlp: str) -> dict[str, Any]:
    kind = str(data.get("kind") or ("cve" if data.get("cve_ids") else "news")).lower()
    if kind not in ("cve", "news", "advisory"):
        raise IntelError(f"kind must be cve, news or advisory (got {kind})")
    title = (str(data.get("title") or "").strip())[:500]
    cves = _cves(data.get("cve_ids") or data.get("cve") or data.get("cve_id"))
    if not title and cves:
        title = cves[0]
    if not title:
        raise IntelError("title is required")
    if kind == "cve" and not cves:
        raise IntelError("a CVE-linked item needs at least one CVE ID")
    tlp = str(data.get("tlp") or default_tlp).upper().replace("TLP:", "")
    if tlp == "WHITE":
        tlp = "CLEAR"
    if tlp not in engine.TLP:
        raise IntelError(f"TLP must be one of {', '.join(engine.TLP)}")
    url = str(data.get("url") or "").strip() or None
    if url and not url.startswith(("https://", "http://")):
        raise IntelError("url must be http(s)")
    tags = data.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.replace(";", ",").split(",") if t.strip()]
    refs = data.get("references") or []
    if isinstance(refs, str):
        refs = [r.strip() for r in refs.split() if r.strip()]
    return {"kind": kind, "title": title, "cve_ids": cves, "summary": (str(data.get("summary") or "") or None),
            "description": (str(data.get("description") or "") or None),
            "severity": engine.to_severity(data.get("severity")), "exploited": engine.to_bool(data.get("exploited")),
            "url": url, "references": [r for r in refs if str(r).startswith("http")][:20],
            "published_at": engine.to_dt(data.get("published_at") or data.get("published")),
            "tags": [str(t)[:64] for t in tags][:20], "tlp": tlp,
            "analyst_notes": (str(data.get("analyst_notes") or data.get("notes") or "") or None)}


def parse_import(data: bytes, filename: str) -> tuple[list[dict[str, Any]], str]:
    """CSV / JSON (list of objects) / STIX 2.1 bundle → raw rows (validated separately)."""
    if len(data) > 20_000_000:
        raise IntelError("file too large (20 MB maximum)")
    name = filename.lower()
    text = data.decode("utf-8-sig", errors="replace")
    if name.endswith(".csv"):
        rows = list(csv.DictReader(io.StringIO(text)))
        return rows[:IMPORT_MAX_ROWS + 1], "csv"
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise IntelError("not valid JSON (use .csv for CSV files)") from exc
    if isinstance(doc, dict) and doc.get("type") == "bundle":
        recs, skipped = engine.stix_records(doc.get("objects") or [])
        rows = [{**r.public(), "external_id": r.external_id} for r in recs]
        return rows[:IMPORT_MAX_ROWS + 1], f"stix ({skipped} non-vulnerability/report objects ignored)"
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)][:IMPORT_MAX_ROWS + 1], "json"
    raise IntelError("JSON must be a list of objects or a STIX 2.1 bundle")


def validate_import(rows: list[dict[str, Any]], *, default_tlp: str) -> tuple[list[dict[str, Any]], list[dict]]:
    if len(rows) > IMPORT_MAX_ROWS:
        raise IntelError(f"too many rows (maximum {IMPORT_MAX_ROWS})")
    ok, errors = [], []
    for n, row in enumerate(rows, start=1):
        try:
            item = normalize_manual(row, default_tlp=default_tlp)
            item["external_id"] = str(row.get("external_id") or row.get("id") or "")[:255] or None
            ok.append(item)
        except IntelError as exc:
            errors.append({"row": n, "error": str(exc)})
    return ok, errors


def create_manual(db: Session, sub: IntelSubscription, item: dict[str, Any], *, actor: str) -> IntelItem:
    import uuid

    ext = item.pop("external_id", None) or f"manual-{uuid.uuid4().hex[:16]}"
    existing = db.scalar(select(IntelItem).where(IntelItem.subscription_id == sub.id, IntelItem.external_id == ext))
    row = existing or IntelItem(subscription_id=sub.id, external_id=ext, created_by=actor)
    for k, v in item.items():
        setattr(row, k, v)
    row.is_manual = True
    if existing is None:
        db.add(row)
    return row


def now_utc() -> datetime:
    return datetime.now(UTC)

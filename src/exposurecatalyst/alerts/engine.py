"""Alert evaluation and delivery (runs after every scheduler tick; also callable on demand).

evaluate: for each enabled rule, CVEs updated since the rule's cursor (plus KEV_ADDED events) are matched
          against the criteria; each (rule, CVE) is recorded once in alert_events.
deliver:  pending events are sent per rule — immediately (throttled to one notification per
          ``throttle_minutes``) or as a digest every ``digest_minutes`` — by email, Slack or Teams.
"""

from __future__ import annotations

import json
from datetime import timedelta
from email.message import EmailMessage
from typing import Any

import httpx
import structlog
from markupsafe import escape
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.models import AlertEvent, AlertRule, AssetFinding, Cve, CveEvent, Role, User
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box

log = structlog.get_logger(__name__)
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WEBHOOK_HOSTS = {
    "slack": ["hooks.slack.com"],
    "teams": ["*.webhook.office.com", "*.logic.azure.com", "*.powerplatform.com"],
}
MAX_PER_MESSAGE = 50
EVAL_BATCH = 5000
TRANSPORTS: dict[str, httpx.BaseTransport] = {}  # test hook


def load_webhooks(rule: AlertRule) -> dict[str, str]:
    return json.loads(get_secret_box().decrypt(rule.webhooks_enc)) if rule.webhooks_enc else {}


def store_webhooks(rule: AlertRule, hooks: dict[str, str]) -> None:
    hooks = {k: v for k, v in hooks.items() if v}
    rule.webhooks_enc = get_secret_box().encrypt(json.dumps(hooks)) if hooks else None


def match(rule: AlertRule, cve: Cve, *, kev_added: bool, asset_count: int) -> str | None:
    """Return a human-readable reason if the CVE matches every configured criterion, else None."""
    c = rule.criteria or {}
    reasons: list[str] = []
    if c.get("min_severity"):
        if SEV_RANK.get(cve.severity, 0) < SEV_RANK.get(c["min_severity"], 99):
            return None
        reasons.append(f"severity {cve.severity}")
    if c.get("cvss_min") is not None:
        if cve.cvss_score is None or cve.cvss_score < float(c["cvss_min"]):
            return None
        reasons.append(f"CVSS {cve.cvss_score}")
    if c.get("epss_min") is not None:
        if cve.epss_score is None or cve.epss_score < float(c["epss_min"]):
            return None
        reasons.append(f"EPSS {cve.epss_score * 100:.1f}%")
    if c.get("kev_added"):
        if not kev_added:
            return None
        reasons.append("added to CISA KEV")
    if c.get("vendors") or c.get("products"):
        vendors = {v.lower() for v in c.get("vendors") or []}
        products = {p.lower() for p in c.get("products") or []}
        hit = [
            p
            for p in cve.products
            if (not vendors or any(v in p.vendor.lower() for v in vendors))
            and (not products or any(x in p.product.lower() for x in products))
        ]
        if not hit:
            return None
        reasons.append(f"watchlist {hit[0].vendor}/{hit[0].product}")
    if c.get("keywords"):
        text = f"{cve.title or ''} {cve.description or ''}".lower()
        kw = next((k for k in c["keywords"] if k.lower() in text), None)
        if kw is None:
            return None
        reasons.append(f"keyword '{kw}'")
    if c.get("affected_assets"):
        if asset_count <= 0:
            return None
        reasons.append(f"{asset_count} affected asset(s)")
    return ", ".join(reasons) or "matches rule"


def evaluate(db: Session, now=None) -> int:
    now = now or utcnow()
    created = 0
    for rule in db.scalars(select(AlertRule).where(AlertRule.enabled.is_(True))):
        since = as_utc(rule.cursor_at) or as_utc(rule.created_at)
        kev_ids = set(
            db.scalars(
                select(Cve.cve_id)
                .join(CveEvent, CveEvent.cve_pk == Cve.id)
                .where(CveEvent.event_type == "KEV_ADDED", CveEvent.occurred_at > since)
            )
        )
        cves = list(
            db.scalars(
                select(Cve)
                .where(or_(Cve.updated_at > since, Cve.cve_id.in_(kev_ids)) if kev_ids else Cve.updated_at > since)
                .order_by(Cve.updated_at)
                .limit(EVAL_BATCH)
            )
        )
        seen = (
            set(
                db.scalars(
                    select(AlertEvent.cve_id).where(
                        AlertEvent.rule_id == rule.id, AlertEvent.cve_id.in_([c.cve_id for c in cves])
                    )
                )
            )
            if cves
            else set()
        )
        counts = (
            dict(
                db.execute(
                    select(AssetFinding.cve_id, func.count())
                    .where(AssetFinding.cve_id.in_([c.cve_id for c in cves]))
                    .group_by(AssetFinding.cve_id)
                ).all()
            )
            if cves
            else {}
        )
        for cve in cves:
            if cve.cve_id in seen:
                continue
            reason = match(rule, cve, kev_added=cve.cve_id in kev_ids, asset_count=counts.get(cve.cve_id, 0))
            if reason:
                db.add(AlertEvent(rule_id=rule.id, cve_id=cve.cve_id, reason=reason[:300], matched_at=now))
                created += 1
        rule.cursor_at = as_utc(cves[-1].updated_at) if len(cves) == EVAL_BATCH else now
    db.flush()
    return created


def _recipients(db: Session, rule: AlertRule) -> list[str]:
    r = rule.recipients or {}
    emails = {e.lower() for e in r.get("emails", [])}
    if r.get("user_ids"):
        emails |= {
            u.email
            for u in db.scalars(select(User).where(User.id.in_(r["user_ids"]), User.is_active.is_(True)))
            if u.email
        }
    if r.get("role_ids"):
        for role in db.scalars(select(Role).where(Role.id.in_(r["role_ids"]))):
            emails |= {u.email for u in role.users if u.email and u.is_active}
    return sorted(emails)


def _lines(db: Session, events: list[AlertEvent]) -> list[dict[str, Any]]:
    cves = {c.cve_id: c for c in db.scalars(select(Cve).where(Cve.cve_id.in_([e.cve_id for e in events])))}
    out = []
    for e in events[:MAX_PER_MESSAGE]:
        c = cves.get(e.cve_id)
        out.append(
            {
                "cve_id": e.cve_id,
                "title": (c.title if c else "") or "",
                "severity": c.severity if c else "",
                "cvss": c.cvss_score if c else None,
                "kev": bool(c and c.kev),
                "reason": e.reason,
            }
        )
    return out


def _send_email(db: Session, settings: Settings, rule: AlertRule, lines: list[dict], extra: int, to: list[str]) -> None:
    from exposurecatalyst.advisories.delivery import send
    from exposurecatalyst.advisories.render import LOGO_CID, logo_bytes
    from exposurecatalyst.api.smtp import load_config

    cfg = load_config(db)
    if cfg is None:
        raise RuntimeError("SMTP is not configured")
    base = settings.public_url.rstrip("/")
    msg = EmailMessage()
    msg["Subject"] = f"[ExposureCatalyst alert] {rule.name}: {len(lines) + extra} CVE(s)"[:250]
    msg["From"], msg["To"] = cfg.from_address, ", ".join(to)
    text = "\n".join(
        f"- {x['cve_id']} [{x['severity']}] {x['title']} ({x['reason']}) {base}/cves/{x['cve_id']}" for x in lines
    )
    msg.set_content(f"Alert rule '{rule.name}' matched:\n\n{text}\n" + (f"\n…and {extra} more.\n" if extra else ""))
    rows = "".join(
        f'<tr><td style="padding:6px 8px;border:1px solid #D5DBE4;">'
        f'<a href="{escape(base)}/cves/{escape(x["cve_id"])}" '
        f'style="color:#0B1B33;">{escape(x["cve_id"])}</a></td><td style="padding:6px 8px;border:1px solid #D5DBE4;">'
        f'{escape(x["severity"])}</td><td style="padding:6px 8px;border:1px solid #D5DBE4;">{escape(x["title"])}</td>'
        f'<td style="padding:6px 8px;border:1px solid #D5DBE4;">{escape(x["reason"])}</td></tr>'
        for x in lines
    )
    msg.add_alternative(
        f'<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="font-family:Inter,'
        f'Arial,sans-serif;font-size:13px;color:#0B1B33;border:1px solid #D5DBE4;"><tr><td style="padding:16px 20px;'
        f'border-bottom:4px solid #E8541A;"><img src="cid:{LOGO_CID}" width="211" height="40" alt="ExposureCatalyst" '
        f'style="display:block;border:0;" /></td></tr><tr><td style="padding:16px 20px;"><p style="margin:0 0 10px 0;">'
        f'Alert rule <strong>{escape(rule.name)}</strong> matched:</p><table cellpadding="0" cellspacing="0" '
        f'border="0" style="border-collapse:collapse;width:100%;"><tr style="background:#0B1B33;color:#FFFFFF;">'
        f'<th style="padding:6px 8px;text-align:left;">CVE</th><th style="padding:6px 8px;text-align:left;">Severity'
        f'</th><th style="padding:6px 8px;text-align:left;">Title</th><th style="padding:6px 8px;text-align:left;">Why'
        f"</th></tr>{rows}</table>{f'<p>…and {extra} more.</p>' if extra else ''}</td></tr></table>",
        subtype="html",
    )
    msg.get_payload()[1].add_related(
        logo_bytes(),
        maintype="image",
        subtype="png",
        cid=f"<{LOGO_CID}>",
        filename="exposurecatalyst.png",
        disposition="inline",
    )
    send(msg, to, cfg, settings)


def _post_webhook(settings: Settings, kind: str, url: str, rule: AlertRule, lines: list[dict], extra: int) -> None:
    base = settings.public_url.rstrip("/")
    bullet = "\n".join(
        f"• <{base}/cves/{x['cve_id']}|{x['cve_id']}> [{x['severity']}] {x['title'][:120]} — {x['reason']}"
        for x in lines
    )
    if kind == "slack":
        payload: dict[str, Any] = {
            "text": f"*ExposureCatalyst alert — {rule.name}*\n{bullet}" + (f"\n…and {extra} more" if extra else "")
        }
    else:  # Teams Workflows / incoming webhook: Adaptive Card
        facts = [
            {
                "type": "TextBlock",
                "wrap": True,
                "text": f"[{x['cve_id']}]({base}/cves/{x['cve_id']}) **{x['severity']}** "
                f"{x['title'][:120]} — {x['reason']}",
            }
            for x in lines
        ]
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "body": [
                            {
                                "type": "TextBlock",
                                "weight": "Bolder",
                                "size": "Medium",
                                "text": f"ExposureCatalyst alert — {rule.name}",
                            },
                            *facts,
                        ],
                    },
                }
            ],
        }
    client = SourceClient(
        f"alert-{kind}", settings, rate=1, per=1.0, allowlist=WEBHOOK_HOSTS[kind], transport=TRANSPORTS.get(kind)
    )
    try:
        client.request("POST", url, json=payload, ok_statuses=(200, 202, 204))
    finally:
        client.close()


def deliver(
    db: Session, settings: Settings, now=None, *, rule_ids: list[int] | None = None, force: bool = False
) -> int:
    now = now or utcnow()
    sent = 0
    stmt = select(AlertRule).where(AlertRule.enabled.is_(True))
    if rule_ids:
        stmt = stmt.where(AlertRule.id.in_(rule_ids))
    for rule in db.scalars(stmt):
        pending = list(
            db.scalars(
                select(AlertEvent)
                .where(AlertEvent.rule_id == rule.id, AlertEvent.status == "pending")
                .order_by(AlertEvent.matched_at)
            )
        )
        if not pending:
            continue
        last = as_utc(rule.last_delivered_at)
        wait = timedelta(minutes=rule.digest_minutes if rule.mode == "digest" else rule.throttle_minutes)
        if not force and last and now - last < wait:
            continue
        lines, extra = _lines(db, pending), max(0, len(pending) - MAX_PER_MESSAGE)
        errors = []
        hooks = load_webhooks(rule)
        for ch in rule.channels or []:
            try:
                if ch == "email":
                    to = _recipients(db, rule)
                    if to:
                        _send_email(db, settings, rule, lines, extra, to)
                elif ch in ("slack", "teams") and hooks.get(ch):
                    _post_webhook(settings, ch, hooks[ch], rule, lines, extra)
            except Exception as exc:  # noqa: BLE001 - per-channel isolation
                errors.append(f"{ch}: {type(exc).__name__}: {str(exc)[:150]}")
        status = "error" if errors and len(errors) == len(rule.channels or []) else "sent"
        for e in pending:
            e.status, e.delivered_at = status, now
        rule.last_delivered_at, rule.last_error = now, "; ".join(errors) or None
        audit.record(
            db,
            "alert.triggered",
            actor_username="scheduler",
            target_type="alert_rule",
            target_id=rule.id,
            outcome="failure" if status == "error" else "success",
            details={
                "rule": rule.name,
                "cves": [x["cve_id"] for x in lines],
                "more": extra,
                "channels": rule.channels,
                "errors": errors,
            },
        )
        log.info("alert_delivered", rule=rule.name, cves=len(pending), status=status)
        sent += len(pending)
    db.flush()
    return sent


def run(settings: Settings, session_factory) -> None:
    with session_factory() as db:
        try:
            evaluate(db)
            deliver(db, settings)
            db.commit()
        except Exception:  # noqa: BLE001 - alerting must never break ingestion
            db.rollback()
            log.exception("alert_run_failed")

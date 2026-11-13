"""AI policy, routing with fallback, usage/cost tracking and feature prompts."""

from __future__ import annotations

import json
import re
import time
from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.ai.guard import SYSTEM_BASE, Redactor, fence
from exposurecatalyst.ai.providers import CATALOG, Adapter, AiError
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.models import AiProvider, AiUsage, AppSetting, AssetFinding, Cve, NewsFeed, NewsItem, User
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.security.middleware import SlidingWindowLimiter

log = structlog.get_logger(__name__)
POLICY_KEY = "ai.policy"
FEATURES = {
    "cve_summary": "CVE plain-English and executive summaries",
    "risk_narrative": "Contextual risk narrative (CVSS, EPSS, KEV, exploit, exposure)",
    "remediation": "Remediation and compensating-control guidance",
    "advisory_draft": "Draft advisory body and subject (human-reviewed)",
    "news_brief": "News summarization, clustering, threat actors and campaigns",
    "nl_search": "Natural-language CVE search",
    "chat": "Analyst chat assistant",
    "help": "Ask Help (answers only from help content, with citations)",
}
DEFAULT_POLICY: dict[str, Any] = {
    "enabled": False,
    "allowed_kinds": [],
    "redact_external": True,
    "redact_self_hosted": False,
    "routes": {},
    "monthly_budget_usd": None,
}
_limiters: dict[int, SlidingWindowLimiter] = {}


class AiDisabledError(AiError):
    pass


def load_policy(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, POLICY_KEY)
    return {**DEFAULT_POLICY, **(row.value if row and row.value else {})}


def save_policy(db: Session, policy: dict[str, Any], actor: str) -> None:
    row = db.get(AppSetting, POLICY_KEY)
    if row is None:
        db.add(AppSetting(key=POLICY_KEY, value=policy, updated_by=actor))
    else:
        row.value, row.updated_by = policy, actor


def load_secrets(p: AiProvider) -> dict[str, str]:
    return json.loads(get_secret_box().decrypt(p.secrets_enc)) if p.secrets_enc else {}


def store_secrets(p: AiProvider, secrets: dict[str, str]) -> None:
    secrets = {k: v for k, v in secrets.items() if v}
    p.secrets_enc = get_secret_box().encrypt(json.dumps(secrets)) if secrets else None


def kind_allowed(policy: dict[str, Any], kind: str) -> bool:
    allowed = policy.get("allowed_kinds") or []
    return not allowed or kind in allowed


def month_cost(db: Session) -> float:
    start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return float(
        db.scalar(select(func.coalesce(func.sum(AiUsage.cost_usd), 0.0)).where(AiUsage.occurred_at >= start)) or 0
    )


def candidates(db: Session, policy: dict[str, Any], feature: str) -> list[tuple[AiProvider, str]]:
    routes = (policy.get("routes") or {}).get(feature) or (policy.get("routes") or {}).get("default") or []
    out: list[tuple[AiProvider, str]] = []
    for r in routes:
        p = db.get(AiProvider, int(r.get("provider_id", 0)))
        if p and p.enabled and kind_allowed(policy, p.kind):
            out.append((p, r.get("model") or p.default_model))
    if not out:  # no explicit route: first enabled, allowed provider
        for p in db.scalars(select(AiProvider).where(AiProvider.enabled.is_(True)).order_by(AiProvider.id)):
            if kind_allowed(policy, p.kind):
                out.append((p, p.default_model))
                break
    return out


def _cost(p: AiProvider, inp: int, outp: int) -> float:
    prices = p.config or {}
    return round(
        inp / 1e6 * float(prices.get("price_in_per_mtok") or 0)
        + outp / 1e6 * float(prices.get("price_out_per_mtok") or 0),
        6,
    )


def call(
    db: Session,
    settings: Settings,
    user: User | None,
    feature: str,
    *,
    task: str,
    context: list[tuple[str, str]],
    question: str,
    redactor: Redactor | None = None,
    json_mode: bool = False,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    policy = load_policy(db)
    if not policy["enabled"]:
        raise AiDisabledError("AI features are disabled by your administrator")
    if user is not None:
        lim = _limiters.setdefault(
            settings.ai_rate_limit_per_user_per_minute, SlidingWindowLimiter(settings.ai_rate_limit_per_user_per_minute)
        )
        if not lim.allow(f"ai:{user.id}"):
            raise AiError("Too many AI requests — try again in a minute")
    budget = policy.get("monthly_budget_usd")
    if budget is not None and month_cost(db) >= float(budget):
        raise AiError("The monthly AI budget has been reached")
    routes = candidates(db, policy, feature)
    if not routes:
        raise AiDisabledError("No enabled, allowed AI provider is configured for this feature")
    errors: list[str] = []
    for provider, model in routes:
        spec = CATALOG[provider.kind]
        red = redactor or Redactor()
        red.enabled = policy["redact_self_hosted"] if spec.self_hosted else policy["redact_external"]
        per_block = max(1000, settings.ai_max_context_chars // max(1, len(context)))
        blocks = "\n\n".join(fence(label, red.redact(text), per_block) for label, text in context)
        user_msg = (blocks + "\n\n" if blocks else "") + fence("user request", red.redact(question), 4000)
        msgs = [
            *({"role": m["role"], "content": red.redact(m["content"])[:4000]} for m in (history or [])[-6:]),
            {"role": "user", "content": user_msg},
        ]
        adapter = Adapter(spec, provider.base_url, load_secrets(provider), provider.config or {}, settings)
        started = time.perf_counter()
        usage = AiUsage(
            user_id=user.id if user else None,
            feature=feature,
            provider_id=provider.id,
            provider_name=provider.name,
            model=model,
            redacted=red.enabled and red.count > 0,
        )
        try:
            res = adapter.complete(
                f"{SYSTEM_BASE}\n\nTask: {task}",
                msgs,
                model=model,
                temperature=provider.temperature,
                max_tokens=provider.max_tokens,
                json_mode=json_mode,
            )
            usage.input_tokens, usage.output_tokens = res.input_tokens, res.output_tokens
            usage.cost_usd = _cost(provider, res.input_tokens, res.output_tokens)
            usage.latency_ms = int((time.perf_counter() - started) * 1000)
            db.add(usage)
            provider.status, provider.last_error = "ok", None
            db.commit()
            return {
                "text": red.restore(res.text)[:20_000],
                "provider": provider.name,
                "model": model,
                "redacted_values": red.count if red.enabled else 0,
                "fallbacks": errors,
            }
        except AiError as exc:
            usage.status, usage.error = "error", str(exc)[:500]
            usage.latency_ms = int((time.perf_counter() - started) * 1000)
            provider.status, provider.last_error = "error", str(exc)[:500]
            db.add(usage)
            db.commit()
            errors.append(f"{provider.name}: {str(exc)[:200]}")
        finally:
            adapter.close()
    raise AiError("All AI providers failed: " + "; ".join(errors))


def extract_json(text: str) -> dict[str, Any]:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise AiError("The model did not return JSON")
    try:
        data = json.loads(m.group(0))
    except ValueError as exc:
        raise AiError("The model returned malformed JSON") from exc
    if not isinstance(data, dict):
        raise AiError("The model returned an unexpected JSON shape")
    return data


# ---- context builders ---------------------------------------------------------------------------


def cve_context(db: Session, cve: Cve, red: Redactor) -> tuple[str, str]:
    findings = list(db.scalars(select(AssetFinding).where(AssetFinding.cve_id == cve.cve_id)).all())
    red.known("HOST", [f.hostname for f in findings])
    red.known("IP", [f.ip_address for f in findings])
    red.known("OWNER", [f.owner for f in findings])
    red.known("RESOURCE", [f.resource_id for f in findings])
    red.known("ACCOUNT", [f.cloud_account for f in findings])
    envs: dict[str, int] = {}
    for f in findings:
        envs[f.environment or "unknown"] = envs.get(f.environment or "unknown", 0) + 1
    products = ", ".join(sorted({f"{p.vendor} {p.product}" for p in cve.products})[:15])
    sample = "\n".join(
        f"- {f.hostname or f.ip_address or f.resource_id} ({f.environment or 'env?'}, owner {f.owner or '?'})"
        for f in findings[:15]
    )
    text = (
        f"CVE: {cve.cve_id}\nTitle: {cve.title}\nDescription: {cve.description}\nSeverity: {cve.severity}\n"
        f"CVSS: {cve.cvss_score} (v{cve.cvss_version}) {cve.cvss_vector or ''}\n"
        f"EPSS: {cve.epss_score} (percentile {cve.epss_percentile})\n"
        f"CISA KEV: {'yes, due ' + str(cve.kev_due_date) if cve.kev else 'no'}"
        f"\nKEV required action: {cve.kev_required_action or '-'}"
        f"\nPublic exploit: {'yes' if cve.exploit_available else 'no known'}"
        f"\nCWE: {', '.join(cve.cwes or [])}\nAffected products: {products}\nVendor/patch references: "
        f"{', '.join((cve.patch_refs or [])[:5])}\n\n"
        f"Our exposure (from integrations): {len(findings)} asset finding(s); "
        f"by environment: {envs or 'none recorded'}\n{sample}"
    )
    return f"cve {cve.cve_id}", text


INSIGHT_TASKS = {
    "plain": "Explain this CVE in plain English for an IT engineer: what is affected, how it is exploited, why it "
    "matters, and what to do. 120–200 words, Markdown, short paragraphs.",
    "executive": "Write a 3–5 sentence executive summary for leadership: business risk, likelihood (use EPSS and KEV), "
    "our exposure, and the decision needed. No jargon.",
    "risk": "Write a contextual risk narrative combining severity (CVSS), likelihood (EPSS percentile, KEV, public "
    "exploit) and our exposure (asset counts, environments). Conclude with a priority: P1 (act now), P2 "
    "(this SLA cycle) or P3 (routine), and justify it. Markdown, ≤ 250 words.",
    "remediation": "Give remediation guidance: the fix (patch/upgrade versions if known from the data), interim "
    "compensating controls (configuration, network restrictions, detection ideas), and verification "
    "steps. Use Markdown bullet lists. Do not invent version numbers that are not in the data.",
}


def news_context(db: Session, days: int, limit: int = 60) -> tuple[list[NewsItem], str]:
    feeds = {f.id: f.name for f in db.scalars(select(NewsFeed))}
    items = list(
        db.scalars(
            select(NewsItem)
            .where(NewsItem.published_at >= utcnow() - timedelta(days=days))
            .order_by(NewsItem.published_at.desc())
            .limit(limit)
        )
    )
    text = "\n".join(
        f"[{i.id}] {i.published_at:%Y-%m-%d} {feeds.get(i.feed_id, '?')}: {i.title} — {i.summary or ''} "
        f"CVEs: {', '.join(i.cve_ids or []) or '-'}"
        for i in items
    )
    return items, text

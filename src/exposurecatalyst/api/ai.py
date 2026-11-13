"""AI features (ai:use) and Settings → AI Providers (ai:manage)."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.ai import service as ai
from exposurecatalyst.ai.guard import Redactor
from exposurecatalyst.ai.providers import CATALOG, Adapter, AiError, validate_endpoint
from exposurecatalyst.api.cves import CveQuery, CveSummary, _summary, build_query
from exposurecatalyst.api.deps import Principal, current_principal, require, settings_dep
from exposurecatalyst.api.help import repo as help_repo
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.normalize import CVE_ID_RE
from exposurecatalyst.models import Advisory, AiProvider, AiUsage, Cve
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P
from exposurecatalyst.security.ssrf import UnsafeURLError

router = APIRouter(prefix="/api/ai", tags=["ai"])


def _run(fn):
    try:
        return fn()
    except ai.AiDisabledError as exc:
        raise HTTPException(409, str(exc)) from exc
    except AiError as exc:
        raise HTTPException(502, str(exc)) from exc


def _cve(db: Session, cve_id: str) -> Cve:
    cve_id = cve_id.upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(422, "Invalid CVE ID")
    cve = db.scalar(select(Cve).where(Cve.cve_id == cve_id))
    if cve is None:
        raise HTTPException(404, "CVE not found")
    return cve


@router.get("/status")
def status(p: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    pol = ai.load_policy(db)
    has = bool(ai.candidates(db, pol, "default")) if pol["enabled"] else False
    return {"enabled": pol["enabled"] and has and p.has(P.AI_USE), "features": list(ai.FEATURES)}


# ---- features ------------------------------------------------------------------------------------


class InsightIn(BaseModel):
    kind: Literal["plain", "executive", "risk", "remediation"] = "plain"


@router.post("/cves/{cve_id}/insight")
def cve_insight(
    cve_id: str,
    body: InsightIn,
    p: Principal = Depends(require(P.AI_USE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    cve = _cve(db, cve_id)
    red = Redactor()
    ctx = ai.cve_context(db, cve, red)
    feature = {
        "plain": "cve_summary",
        "executive": "cve_summary",
        "risk": "risk_narrative",
        "remediation": "remediation",
    }[body.kind]
    return _run(
        lambda: ai.call(
            db,
            settings,
            p.user,
            feature,
            task=ai.INSIGHT_TASKS[body.kind],
            context=[ctx],
            question=f"Produce the {body.kind} analysis for {cve.cve_id}.",
            redactor=red,
        )
    )


DRAFT_TASK = (
    "Draft advisory email sections for stakeholders. Return ONLY a JSON object with string fields: "
    '"subject" (≤ 200 chars; keep the advisory ID and CVE ID), "summary", "business_impact", '
    '"remediation", "workaround". Plain text (no HTML, no Markdown headings). Base everything on the data; '
    "if something is unknown, say so. A human will review before sending."
)


@router.post("/advisories/{advisory_pk}/draft")
def advisory_draft(
    advisory_pk: int,
    p: Principal = Depends(require(P.AI_USE, P.ADVISORY_CREATE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    adv = db.get(Advisory, advisory_pk)
    if adv is None:
        raise HTTPException(404, "Advisory not found")
    cve = _cve(db, adv.cve_id)
    red = Redactor()
    red.known("HOST", [a.hostname for a in adv.assets])
    red.known("IP", [a.ip_address for a in adv.assets])
    red.known("OWNER", [a.owner for a in adv.assets] + [adv.owner_contact])
    ctx = [
        ai.cve_context(db, cve, red),
        (
            "advisory",
            f"Advisory ID: {adv.advisory_id}\nSeverity: {adv.severity}\nCurrent subject: {adv.subject}\n"
            f"SLA due: {adv.sla_due_date}\nAsset rows: {len(adv.assets)}\nOwner: {adv.owner_contact or '-'}",
        ),
    ]
    res = _run(
        lambda: ai.call(
            db,
            settings,
            p.user,
            "advisory_draft",
            task=DRAFT_TASK,
            context=ctx,
            question="Draft the advisory sections.",
            redactor=red,
            json_mode=True,
        )
    )
    data = _run(lambda: ai.extract_json(res["text"]))
    limits = {"subject": 300, "summary": 20_000, "business_impact": 20_000, "remediation": 20_000, "workaround": 20_000}
    suggestion = {k: str(data[k]).replace("\r", "")[:n] for k, n in limits.items() if isinstance(data.get(k), str)}
    if "subject" in suggestion:
        suggestion["subject"] = " ".join(suggestion["subject"].split())
    return {
        **{k: v for k, v in res.items() if k != "text"},
        "suggestion": suggestion,
        "note": "Suggestions only — nothing was saved. Review, edit and apply in the editor.",
    }


class NewsBriefIn(BaseModel):
    days: int = Field(3, ge=1, le=14)


NEWS_TASK = (
    "Summarize the security news items for a SOC morning brief. Return ONLY JSON: "
    '{"summary": "Markdown, ≤ 250 words", "themes": [{"title": "...", "item_ids": [ids]}], '
    '"actors": [{"name": "threat actor or group", "campaign": "campaign/malware or null", '
    '"item_ids": [ids]}]}. Use only item ids that appear in the data, in [brackets]. Cluster related '
    "stories into themes. Only list actors explicitly named in the items."
)


@router.post("/news/brief")
def news_brief(
    body: NewsBriefIn,
    p: Principal = Depends(require(P.AI_USE, P.NEWS_VIEW)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    items, text = ai.news_context(db, body.days)
    if not items:
        raise HTTPException(409, "No news items in that period yet")
    res = _run(
        lambda: ai.call(
            db,
            settings,
            p.user,
            "news_brief",
            task=NEWS_TASK,
            context=[("news items", text)],
            question=f"Brief for the last {body.days} day(s).",
            json_mode=True,
        )
    )
    data = _run(lambda: ai.extract_json(res["text"]))
    valid = {i.id: i for i in items}

    def ids(v: Any) -> list[int]:
        return [int(x) for x in (v or []) if str(x).isdigit() and int(x) in valid][:20]

    themes = [
        {
            "title": str(t.get("title", ""))[:200],
            "items": [{"id": i, "title": valid[i].title, "url": valid[i].url} for i in ids(t.get("item_ids"))],
        }
        for t in data.get("themes", [])
        if isinstance(t, dict)
    ][:10]
    actors = [
        {
            "name": str(a.get("name", ""))[:100],
            "campaign": (str(a["campaign"])[:100] if a.get("campaign") else None),
            "items": ids(a.get("item_ids")),
        }
        for a in data.get("actors", [])
        if isinstance(a, dict) and a.get("name")
    ][:20]
    actors = [a for a in actors if a["items"]]  # an actor must be grounded in at least one real item
    return {
        **{k: v for k, v in res.items() if k != "text"},
        "summary": str(data.get("summary", ""))[:5000],
        "themes": themes,
        "actors": actors,
        "items_considered": len(items),
    }


class SearchIn(BaseModel):
    q: str = Field(min_length=3, max_length=300)


SEARCH_TASK = (
    "Translate the user's request into CVE search filters. Today is {today}. Return ONLY JSON with any "
    "of: q (keyword), vendor, product, severity (list of CRITICAL/HIGH/MEDIUM/LOW), cvss_min, cvss_max, "
    "epss_min (0-1), kev (bool), exploit (bool), published_from, published_to, modified_from, modified_to "
    "(YYYY-MM-DD), sort (one of -published_at, -last_modified_at, -cvss_score, -epss_score). Omit unknowns."
)


@router.post("/search")
def nl_search(
    body: SearchIn,
    p: Principal = Depends(require(P.AI_USE, P.CVE_VIEW)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    res = _run(
        lambda: ai.call(
            db,
            settings,
            p.user,
            "nl_search",
            task=SEARCH_TASK.format(today=utcnow().date()),
            context=[],
            question=body.q,
            json_mode=True,
        )
    )
    raw = _run(lambda: ai.extract_json(res["text"]))
    allowed = set(CveQuery.model_fields)
    try:  # the model's output is only ever data, validated by the same schema as the search form
        crit = CveQuery(**{k: v for k, v in raw.items() if k in allowed})
    except ValidationError as exc:
        raise HTTPException(502, f"The model proposed invalid filters: {exc.errors()[0]['msg']}") from exc
    rows = db.scalars(build_query(crit).limit(25)).all()
    return {
        **{k: v for k, v in res.items() if k != "text"},
        "filters": crit.model_dump(mode="json", exclude_none=True, exclude_defaults=True),
        "items": [CveSummary.model_validate(_summary(c)).model_dump(mode="json") for c in rows],
    }


class ChatIn(BaseModel):
    messages: list[dict[str, str]] = Field(min_length=1, max_length=20)
    cve_id: str | None = Field(None, max_length=32)


CHAT_TASK = (
    "Answer the analyst's question using ONLY the ExposureCatalyst data provided (CVE records and "
    "exposure). If the data does not contain the answer, say so and suggest where in ExposureCatalyst to "
    "look. Refuse unrelated requests. Markdown, concise."
)


@router.post("/chat")
def chat(
    body: ChatIn,
    p: Principal = Depends(require(P.AI_USE, P.CVE_VIEW)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    msgs = [m for m in body.messages if m.get("role") in ("user", "assistant") and isinstance(m.get("content"), str)]
    if not msgs or msgs[-1]["role"] != "user":
        raise HTTPException(422, "The last message must be from the user")
    question = msgs[-1]["content"][:4000]
    mentioned = re.findall(r"CVE-\d{4}-\d{4,7}", question, flags=re.IGNORECASE)
    ids = {i.upper() for i in [body.cve_id or "", *mentioned] if i and CVE_ID_RE.match(i.upper())}
    red = Redactor()
    ctx = []
    for cid in list(ids)[:5]:
        cve = db.scalar(select(Cve).where(Cve.cve_id == cid))
        if cve:
            ctx.append(ai.cve_context(db, cve, red))
    if not ctx:  # keyword retrieval over titles as a fallback
        words = re.findall(r"[A-Za-z][\w-]{3,}", question)[:4]
        if words:
            crit = CveQuery(q=max(words, key=len), sort="-epss_score")
            rows = db.scalars(build_query(crit).limit(8)).all()
            ctx.append(
                (
                    "cve search results",
                    "\n".join(
                        f"{c.cve_id} [{c.severity}, CVSS {c.cvss_score}, EPSS {c.epss_score}, KEV {c.kev}] {c.title}"
                        for c in rows
                    )
                    or "none",
                )
            )
    return _run(
        lambda: ai.call(
            db,
            settings,
            p.user,
            "chat",
            task=CHAT_TASK,
            context=ctx,
            question=question,
            redactor=red,
            history=msgs[:-1],
        )
    )


class HelpIn(BaseModel):
    question: str = Field(min_length=3, max_length=500)


HELP_TASK = (
    "Answer ONLY from the ExposureCatalyst help topics provided. Cite each topic you used as [topic-id] "
    "using the exact ids from the data. If the topics do not answer the question, reply exactly: "
    '"I couldn\'t find this in the help. Try the Help Center search or contact your administrator." '
    "Markdown, ≤ 200 words."
)


@router.post("/help")
def ask_help(
    body: HelpIn,
    p: Principal = Depends(require(P.AI_USE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    hits = help_repo().search(body.question, p.permissions, limit=4)
    topics = [help_repo().get(h["id"], p.permissions) for h in hits]
    ctx = [
        (f"help topic id={t.id}", f"# {t.title} (id: {t.id})\n" + help_repo().render(t, p.permissions)["markdown"])
        for t in topics
        if t
    ]
    if not ctx:
        return {
            "text": "I couldn't find this in the help. Try the Help Center search or contact your administrator.",
            "citations": [],
        }
    res = _run(lambda: ai.call(db, settings, p.user, "help", task=HELP_TASK, context=ctx, question=body.question))
    valid = {t.id: t for t in topics if t}
    cited = [c for c in dict.fromkeys(re.findall(r"\[([a-z0-9-]+)\]", res["text"])) if c in valid]
    return {**res, "citations": [{"id": c, "title": valid[c].title, "docs": valid[c].docs} for c in cited]}


# ---- Settings → AI Providers ------------------------------------------------------------------


class Route(BaseModel):
    provider_id: int
    model: str | None = Field(None, max_length=200)


class PolicyIn(BaseModel):
    enabled: bool = False
    allowed_kinds: list[str] = Field(default_factory=list)
    redact_external: bool = True
    redact_self_hosted: bool = False
    routes: dict[str, list[Route]] = Field(default_factory=dict)
    monthly_budget_usd: float | None = Field(None, ge=0)


@router.get("/catalog")
def catalog(_: Principal = Depends(require(P.AI_MANAGE))) -> dict:
    return {"providers": [s.public() for s in CATALOG.values()], "features": ai.FEATURES}


@router.get("/policy")
def get_policy(_: Principal = Depends(require(P.AI_MANAGE)), db: Session = Depends(get_db)) -> dict:
    return {**ai.load_policy(db), "month_cost_usd": round(ai.month_cost(db), 4)}


@router.put("/policy")
def put_policy(
    body: PolicyIn, request: Request, p: Principal = Depends(require(P.AI_MANAGE)), db: Session = Depends(get_db)
) -> dict:
    bad = [k for k in body.allowed_kinds if k not in CATALOG]
    if bad:
        raise HTTPException(422, f"Unknown provider kinds: {', '.join(bad)}")
    bad_f = [f for f in body.routes if f not in ai.FEATURES and f != "default"]
    if bad_f:
        raise HTTPException(422, f"Unknown features: {', '.join(bad_f)}")
    for f, chain in body.routes.items():
        for r in chain:
            prov = db.get(AiProvider, r.provider_id)
            if prov is None:
                raise HTTPException(422, f"Route for {f} references an unknown provider")
            if not ai.kind_allowed(body.model_dump(), prov.kind):
                raise HTTPException(422, f"Route for {f} uses {prov.name}, which the allowlist blocks")
    policy = body.model_dump()
    ai.save_policy(db, policy, p.user.username)
    audit.record(
        db,
        "ai.policy_updated",
        actor=p.user,
        request=request,
        target_type="settings",
        target_id="ai.policy",
        details=policy,
    )
    db.commit()
    return get_policy(p, db)


class ProviderIn(BaseModel):
    kind: str
    name: str = Field(min_length=2, max_length=100)
    base_url: str = Field(min_length=8, max_length=500)
    models: list[str] = Field(default_factory=list, max_length=50)
    default_model: str = Field(min_length=1, max_length=200)
    temperature: float = Field(0.2, ge=0, le=2)
    max_tokens: int = Field(1200, ge=64, le=32_000)
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] | None = None
    enabled: bool = False


class ProviderOut(BaseModel):
    id: int
    kind: str
    label: str
    name: str
    enabled: bool
    base_url: str
    models: list[str]
    default_model: str
    temperature: float
    max_tokens: int
    config: dict[str, Any]
    secrets_set: list[str]
    status: str
    last_error: str | None
    blocked_by_allowlist: bool
    self_hosted: bool


def _pout(db: Session, pr: AiProvider) -> ProviderOut:
    spec = CATALOG[pr.kind]
    return ProviderOut(
        id=pr.id,
        kind=pr.kind,
        label=spec.label,
        name=pr.name,
        enabled=pr.enabled,
        base_url=pr.base_url,
        models=pr.models,
        default_model=pr.default_model,
        temperature=pr.temperature,
        max_tokens=pr.max_tokens,
        config=pr.config or {},
        secrets_set=sorted(ai.load_secrets(pr)),
        status=pr.status,
        last_error=pr.last_error,
        blocked_by_allowlist=not ai.kind_allowed(ai.load_policy(db), pr.kind),
        self_hosted=spec.self_hosted,
    )


def _apply(pr: AiProvider, body: ProviderIn, settings: Settings) -> None:
    spec = CATALOG.get(body.kind)
    if spec is None:
        raise HTTPException(422, "Unknown provider kind")
    try:
        pr.base_url = validate_endpoint(spec, body.base_url.strip(), settings)
    except UnsafeURLError as exc:
        raise HTTPException(422, f"Endpoint rejected: {exc}") from exc
    allowed_cfg = {*spec.config_keys, "price_in_per_mtok", "price_out_per_mtok"}
    unknown = set(body.config) - allowed_cfg
    if unknown:
        raise HTTPException(422, f"Unknown config keys: {', '.join(sorted(unknown))}")
    pr.kind, pr.name, pr.enabled = body.kind, body.name.strip(), body.enabled
    pr.models = list(dict.fromkeys([body.default_model, *body.models]))
    pr.default_model, pr.temperature, pr.max_tokens = body.default_model, body.temperature, body.max_tokens
    pr.config = {k: v for k, v in body.config.items() if v not in (None, "")}
    if body.secrets is not None:
        bad = set(body.secrets) - set(spec.secrets)
        if bad:
            raise HTTPException(422, f"Unknown secrets for {spec.label}: {', '.join(sorted(bad))}")
        ai.store_secrets(pr, {**ai.load_secrets(pr), **body.secrets})


@router.get("/providers", response_model=list[ProviderOut])
def list_providers(_: Principal = Depends(require(P.AI_MANAGE)), db: Session = Depends(get_db)):
    return [_pout(db, x) for x in db.scalars(select(AiProvider).order_by(AiProvider.name))]


@router.post("/providers", response_model=ProviderOut, status_code=201)
def create_provider(
    body: ProviderIn,
    request: Request,
    p: Principal = Depends(require(P.AI_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> ProviderOut:
    if db.scalar(select(AiProvider).where(func.lower(AiProvider.name) == body.name.strip().lower())):
        raise HTTPException(409, "A provider with that name exists")
    pr = AiProvider(config={}, models=[])
    _apply(pr, body, settings)
    db.add(pr)
    db.flush()
    audit.record(
        db,
        "ai.provider_created",
        actor=p.user,
        request=request,
        target_type="ai_provider",
        target_id=pr.id,
        details={"kind": pr.kind, "name": pr.name, "base_url": pr.base_url, "secrets_set": sorted(body.secrets or {})},
    )
    db.commit()
    return _pout(db, pr)


@router.put("/providers/{provider_id}", response_model=ProviderOut)
def update_provider(
    provider_id: int,
    body: ProviderIn,
    request: Request,
    p: Principal = Depends(require(P.AI_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> ProviderOut:
    pr = db.get(AiProvider, provider_id)
    if pr is None:
        raise HTTPException(404, "Provider not found")
    _apply(pr, body, settings)
    audit.record(
        db,
        "ai.provider_updated",
        actor=p.user,
        request=request,
        target_type="ai_provider",
        target_id=pr.id,
        details={"name": pr.name, "enabled": pr.enabled, "secrets_changed": sorted(body.secrets or {})},
    )
    db.commit()
    return _pout(db, pr)


@router.delete("/providers/{provider_id}", status_code=204)
def delete_provider(
    provider_id: int, request: Request, p: Principal = Depends(require(P.AI_MANAGE)), db: Session = Depends(get_db)
) -> None:
    pr = db.get(AiProvider, provider_id)
    if pr is None:
        raise HTTPException(404, "Provider not found")
    audit.record(
        db,
        "ai.provider_deleted",
        actor=p.user,
        request=request,
        target_type="ai_provider",
        target_id=pr.id,
        details={"name": pr.name},
    )
    db.delete(pr)
    db.commit()


@router.post("/providers/{provider_id}/test")
def test_provider(
    provider_id: int,
    request: Request,
    p: Principal = Depends(require(P.AI_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    pr = db.get(AiProvider, provider_id)
    if pr is None:
        raise HTTPException(404, "Provider not found")
    spec = CATALOG[pr.kind]
    adapter = Adapter(spec, pr.base_url, ai.load_secrets(pr), pr.config or {}, settings)
    try:  # a fixed, data-free prompt: testing never sends any ExposureCatalyst data
        res = adapter.complete(
            "Reply with the single word OK.",
            [{"role": "user", "content": "ping"}],
            model=pr.default_model,
            temperature=0,
            max_tokens=8,
        )
        pr.status, pr.last_error, ok, msg = "ok", None, True, f"Model replied: {res.text.strip()[:40]!r}"
    except Exception as exc:  # noqa: BLE001
        pr.status, pr.last_error, ok, msg = "error", str(exc)[:500], False, str(exc)[:300]
    finally:
        adapter.close()
    audit.record(
        db,
        "ai.provider_tested",
        actor=p.user,
        request=request,
        target_type="ai_provider",
        target_id=pr.id,
        outcome="success" if ok else "failure",
    )
    db.commit()
    return {"ok": ok, "message": msg}


@router.get("/usage")
def usage(days: int = 30, _: Principal = Depends(require(P.AI_MANAGE)), db: Session = Depends(get_db)) -> dict:
    since = utcnow() - timedelta(days=max(1, min(days, 365)))
    rows = db.execute(
        select(
            AiUsage.provider_name,
            AiUsage.feature,
            AiUsage.status,
            func.count(),
            func.sum(AiUsage.input_tokens),
            func.sum(AiUsage.output_tokens),
            func.sum(AiUsage.cost_usd),
            func.sum(func.cast(AiUsage.redacted, AiUsage.input_tokens.type)),
        )
        .where(AiUsage.occurred_at >= since)
        .group_by(AiUsage.provider_name, AiUsage.feature, AiUsage.status)
    ).all()
    return {
        "since": since,
        "rows": [
            {
                "provider": r[0],
                "feature": r[1],
                "status": r[2],
                "requests": r[3],
                "input_tokens": int(r[4] or 0),
                "output_tokens": int(r[5] or 0),
                "cost_usd": round(float(r[6] or 0), 4),
                "redacted_requests": int(r[7] or 0),
            }
            for r in rows
        ],
    }

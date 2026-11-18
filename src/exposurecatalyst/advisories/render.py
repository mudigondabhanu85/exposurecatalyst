"""Advisory email rendering.

Layout and components are code-owned (branding + Outlook-safe markup). The editable part of a template
(subject + body) is rendered with Jinja's ImmutableSandboxedEnvironment and autoescaping, so template
authors cannot reach Python internals (SSTI) and upstream CVE text cannot inject HTML.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError
from jinja2.sandbox import ImmutableSandboxedEnvironment, SecurityError
from markupsafe import Markup, escape

from exposurecatalyst.advisories.service import (
    Exposure,
    clean_header,
    exposure,
    primary_product,
    product_versions,
    references,
    remediation_timeframes,
)
from exposurecatalyst.config import get_settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.models import Advisory, Cve

TEMPLATES = Path(__file__).parent / "templates"
LOGO_FILE = "logo-light-wordmark@2x.png"  # brand kit asset, unmodified; displayed at 211×40 (h40 size)
LOGO_CID = "excat-logo"
MAX_TEMPLATE_CHARS = 50_000

# Same accessible severity palette as the UI — never brand orange.
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#7A0F1C", "fg": "#FFFFFF"},
    "HIGH": {"bg": "#C21D2F", "fg": "#FFFFFF"},
    "MEDIUM": {"bg": "#FCE38A", "fg": "#5C4200"},
    "LOW": {"bg": "#DCE9FB", "fg": "#14386B"},
}
DEFAULT_SEV = {"bg": "#EEF1F5", "fg": "#0B1B33"}


def nl2br(value: Any) -> Markup:
    return Markup("<br />\n").join(escape(line) for line in str(value or "").splitlines())


_BULLET = ("- ", "* ", "• ", "\u2022")


def bullets(value: Any) -> list[str] | None:
    """Lines of ``value`` when every non-empty line is a bullet ("- ", "* ", "• "), else None."""
    lines = [ln.strip() for ln in str(value or "").splitlines() if ln.strip()]
    if not lines or not all(ln.startswith(_BULLET) for ln in lines):
        return None
    return [re.sub(r"^[-*•\u2022]\s*", "", ln).strip() for ln in lines]


_code_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True, undefined=StrictUndefined)
_code_env.filters["nl2br"] = nl2br
_code_env.globals["bullets"] = bullets
_sandbox = ImmutableSandboxedEnvironment(autoescape=True)
_sandbox.filters["nl2br"] = nl2br


class TemplateValidationError(ValueError):
    pass


@lru_cache
def logo_bytes() -> bytes:
    path = get_settings().brand_dir / "assets" / "png" / LOGO_FILE
    return path.read_bytes()


def logo_data_uri() -> str:
    return "data:image/png;base64," + base64.b64encode(logo_bytes()).decode()


def _cve_view(cve: Cve | None) -> dict[str, Any]:
    if cve is None:
        return {"cvss": "—", "cvss_score": "—", "epss": "—", "kev": "—", "exploit": "—", "kev_listed": False,
                "exploited": "Unknown"}
    cvss = f"{cve.cvss_score:.1f} (CVSS v{cve.cvss_version})" if cve.cvss_score is not None else "Not yet scored"
    if cve.cvss_vector:
        cvss += f" · {cve.cvss_vector}"
    epss = (f"{cve.epss_score * 100:.1f}% (percentile {cve.epss_percentile * 100:.0f})"
            if cve.epss_score is not None and cve.epss_percentile is not None else "Not yet scored")
    kev = f"Yes — known exploited; CISA due {cve.kev_due_date}" if cve.kev else "Not listed"
    exploit = "Public exploit available" if cve.exploit_available else "No public exploit known"
    exploited = "Yes — CISA KEV" if cve.kev else "No known exploitation"
    score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "Not yet scored"
    return {"cvss": cvss, "cvss_score": score, "epss": epss, "kev": kev, "exploit": exploit, "kev_listed": cve.kev,
            "exploited": exploited}


def _fmt_dt(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else None


def build_context(adv: Advisory, cve: Cve | None, exp: Exposure | None = None) -> dict[str, Any]:
    exp = exp or exposure(adv)
    rows = [{"source": r.source, "validated": r.validated, "asset_count": r.asset_count,
             "last_checked": _fmt_dt(r.last_checked), "manual": r.manual, "check": r.check_label,
             "method": r.method_label, "note": r.note or r.finding} for r in exp.rows]
    advisory = {k: getattr(adv, k) for k in (
        "advisory_id", "cve_id", "severity", "title", "summary", "business_impact", "remediation", "workaround",
        "affected_products", "owner_contact", "sla_due_date", "subject", "vuln_type", "owner_actions",
        "support_actions")}
    ctx = {
        "advisory": advisory,
        "cve": _cve_view(cve),
        "exposure": {"rows": rows, "total_unique": exp.total_unique, "manual_uncounted": exp.manual_uncounted,
                     "methodology": exp.methodology, "potential": exp.potential},
        "product": primary_product(cve, adv),
        "products": product_versions(cve),
        "references": references(cve, adv.cve_id),
        "timeframes": [{**t, "due": t["due"].isoformat()} for t in remediation_timeframes(adv)],
    }
    intel = _licensed_intel(adv)
    if intel:  # only with features.subscriptions and per-source email redistribution rights
        ctx["intel"] = intel
    return ctx


def _licensed_intel(adv: Advisory) -> list[dict[str, Any]]:
    from sqlalchemy.orm import object_session

    from exposurecatalyst.config import get_settings

    db = object_session(adv)
    if db is None or not get_settings().features.subscriptions:
        return []
    from exposurecatalyst.subscriptions.service import email_intel

    return email_intel(db, adv.cve_id)


def _components(ctx: dict[str, Any]) -> dict[str, Any]:
    # Markup() here wraps output of an *autoescaping* template, i.e. already-escaped HTML.
    mod = _code_env.get_template("components.html.j2").make_module(ctx)
    out: dict[str, Any] = {name: Markup(getattr(mod, MACRO_NAMES.get(name, name))())  # noqa: S704  # nosec B704
                           for name in COMPONENTS}
    out["section"] = lambda title, text: Markup(mod.section(title, text))  # noqa: S704  # nosec B704
    out["heading"] = lambda title: Markup(mod.heading(title))  # noqa: S704  # nosec B704
    return out


COMPONENTS = ("summary_table", "validation_matrix", "methodology", "tool_summary", "vulnerability_analysis",
              "affected_products_table", "source_notes", "references", "remediation_timeframes", "role_actions")
MACRO_NAMES = {"references": "references_section"}  # macro names that would shadow a context variable


def render_body(body_template: str, ctx: dict[str, Any]) -> Markup:
    if len(body_template) > MAX_TEMPLATE_CHARS:
        raise TemplateValidationError("template body too large")
    try:
        rendered = _sandbox.from_string(body_template).render(**ctx, components=_components(ctx))
        return Markup(rendered)  # noqa: S704  # nosec B704 - sandboxed + autoescaped output
    except (TemplateError, SecurityError) as exc:
        raise TemplateValidationError(f"template error: {exc}") from exc


def render_subject(subject_template: str, ctx: dict[str, Any]) -> str:
    try:
        return clean_header(_sandbox.from_string(subject_template).render(**ctx))
    except (TemplateError, SecurityError) as exc:
        raise TemplateValidationError(f"subject template error: {exc}") from exc


def render_html(adv: Advisory, cve: Cve | None, *, logo_src: str, watermark: str | None = None,
                now: datetime | None = None) -> str:
    ctx = build_context(adv, cve)
    body = render_body(adv.template_version.body_template, ctx)
    return _code_env.get_template("layout.html.j2").render(
        **ctx, subject=adv.subject, body=body, logo_src=logo_src, watermark=watermark,
        sev=SEVERITY_COLORS.get(adv.severity, DEFAULT_SEV), generated_at=_fmt_dt(now or utcnow()))


def render_text(adv: Advisory, cve: Cve | None) -> str:
    """Plain-text alternative part (accessibility, text-only clients, spam scoring)."""
    ctx = build_context(adv, cve)
    a, c, e = ctx["advisory"], ctx["cve"], ctx["exposure"]
    lines = [f"{a['severity']} SECURITY ADVISORY — {a['advisory_id']}", "",
             f"{a['cve_id']} – {a['title'] or ''}".strip(" –"), "",
             f"Severity: {a['severity']}", f"CVSS: {c['cvss']}", f"EPSS: {c['epss']}", f"CISA KEV: {c['kev']}",
             f"Exploit status: {c['exploit']}", f"Affected products: {a['affected_products'] or '-'}",
             f"Affected assets (unique): {e['total_unique']}", f"Remediation due: {a['sla_due_date'] or '-'}",
             f"Owner / contact: {a['owner_contact'] or 'Security Operations'}"]
    if a["vuln_type"]:
        lines.append(f"Type: {a['vuln_type']}")
    lines.append("")
    if e["methodology"]:
        lines += [" ".join(e["methodology"]), ""]
    for title, key in (("Summary", "summary"), ("Business impact", "business_impact"),
                       ("Recommended remediation", "remediation"), ("Workaround", "workaround")):
        if a[key]:
            lines += [title.upper(), a[key], ""]
    if ctx["products"]:
        lines.append("AFFECTED PRODUCTS")
        lines += [f"  {p['product']}  {p['versions']}" for p in ctx["products"]]
        lines.append("")
    lines.append("ASSET VALIDATION MATRIX  (source / check available / validated / assets / last checked)")
    if not e["rows"]:
        lines.append("  No tools selected for this advisory.")
    for r in e["rows"]:
        count = "-" if r["validated"] == "Not Integrated" else r["asset_count"]
        lines.append(f"  {r['source']:<18} {r['check']:<4} {r['validated']:<15} {count!s:>6}  "
                     f"{r['last_checked'] or '-'}" + ("  (Manual)" if r["manual"] else ""))
    notes = [r for r in e["rows"] if r["note"]]
    if notes:
        lines += ["", "NOTES"] + [f"  {r['source']}{' (' + r['method'] + ')' if r['method'] else ''}: {r['note']}"
                                  for r in notes]
    for title, key in (("Risk owner (BISO) actions", "owner_actions"), ("Support team actions", "support_actions")):
        if a[key]:
            lines += ["", title.upper(), a[key]]
    if ctx["timeframes"]:
        lines += ["", "REMEDIATION TIMEFRAMES"] + [f"  {t['asset_class']}: {t['days']} days (due {t['due']})"
                                                   for t in ctx["timeframes"]]
    if ctx["references"]:
        lines += ["", "REFERENCES"] + [f"  {r['label']}: {r['url']}" for r in ctx["references"]]
    if ctx.get("intel"):
        lines += ["", "THREAT INTELLIGENCE (licensed sources)"]
        for i in ctx["intel"]:
            lines.append(f"  [{i['source']} · TLP:{i['tlp']}] {i['title']}")
            for key in ("summary", "description"):
                if i.get(key):
                    lines.append(f"    {i[key]}")
            if i.get("url"):
                lines.append(f"    {i['url']}")
    lines += ["", f"Generated by ExposureCatalyst · Advisory ID {a['advisory_id']} · {_fmt_dt(utcnow())}",
              f"Please quote {a['advisory_id']} in tickets and replies."]
    return "\n".join(lines)


SAMPLE_CTX = {
    "advisory": {"advisory_id": "EXCAT-2026-0001", "cve_id": "CVE-2026-0001", "severity": "HIGH", "title": "Sample",
                 "summary": "s", "business_impact": "b", "remediation": "r", "workaround": "w",
                 "affected_products": "Acme Widget", "owner_contact": "SecOps", "sla_due_date": "2026-12-01",
                 "subject": "s", "vuln_type": "Race condition (CWE-362)", "owner_actions": "- a\n- b",
                 "support_actions": "- c"},
    "cve": {"cvss": "9.8", "cvss_score": "9.8", "epss": "50%", "kev": "Yes", "exploit": "Yes", "kev_listed": True,
            "exploited": "Yes — CISA KEV"},
    "exposure": {"rows": [{"source": "Qualys", "validated": "Yes", "asset_count": 3, "last_checked": None,
                           "manual": False, "check": "Yes", "method": "Vulnerability check", "note": "n"}],
                 "total_unique": 3, "manual_uncounted": 0, "methodology": ["m"], "potential": False},
    "product": "Acme Widget",
    "products": [{"product": "Acme Widget", "versions": "Before 2.0"}],
    "references": [{"label": "NVD – CVE-2026-0001", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}],
    "timeframes": [{"asset_class": "Cloud", "days": 60, "due": "2026-12-01"}],
}


def validate_template(subject_template: str, body_template: str) -> None:
    """Compile and test-render against sample data; raises TemplateValidationError."""
    render_subject(subject_template, SAMPLE_CTX)
    render_body(body_template, SAMPLE_CTX)


DEFAULT_SUBJECT = ("[{{ advisory.severity }}] {{ advisory.advisory_id }} Security Advisory: {{ advisory.cve_id }} – "
                   "{{ product }} – {{ exposure.total_unique }} "
                   "asset{{ '' if exposure.total_unique == 1 else 's' }} affected")
DEFAULT_TEMPLATES = {
    "critical": ("Critical", "Immediate action — critical or actively exploited vulnerabilities"),
    "high": ("High", "High-severity vulnerabilities with a scheduled SLA"),
    "informational": ("Informational", "Awareness advisories for medium/low findings"),
    "executive": ("Executive", "Short executive briefing with exposure and due date"),
    "exposure_analysis": ("Exposure Analysis", "Full vulnerability & exposure analysis: per-tool checks vs instances, "
                          "affected versions, notes, references, role-based actions and remediation timeframes"),
}


def default_body(kind: str) -> str:
    return (TEMPLATES / "defaults" / f"{kind}.html.j2").read_text(encoding="utf-8")

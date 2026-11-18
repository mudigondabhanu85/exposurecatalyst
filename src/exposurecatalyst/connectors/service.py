"""Correlation: ask every enabled integration which assets a CVE affects, cache, enrich, feed advisories."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.connectors.base import REGISTRY, Connector, UnsupportedError, map_record
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import (
    Advisory,
    AdvisoryAsset,
    AdvisorySourceStatus,
    AssetFinding,
    Integration,
    IntegrationCveCheck,
)
from exposurecatalyst.security.crypto import get_secret_box

log = structlog.get_logger(__name__)
ENRICH_LIMIT = 200

# Test hook: tests inject a MockTransport per integration kind.
TRANSPORTS: dict[str, httpx.BaseTransport] = {}


def load_secrets(integration: Integration) -> dict[str, str]:
    if not integration.secrets_enc:
        return {}
    return json.loads(get_secret_box().decrypt(integration.secrets_enc))


def store_secrets(integration: Integration, secrets: dict[str, str]) -> None:
    integration.secrets_enc = get_secret_box().encrypt(json.dumps(secrets)) if secrets else None


def build(integration: Integration, settings: Settings, db: Session | None = None) -> Connector:
    cls = REGISTRY[integration.kind]
    kw: dict[str, Any] = {"transport": TRANSPORTS.get(integration.kind)}
    if integration.kind == "qualys":
        kw["db"] = db
    return cls(integration, load_secrets(integration), settings, **kw)


def _sanitize(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


def test(db: Session, integration: Integration, settings: Settings) -> tuple[bool, str]:
    conn = build(integration, settings, db)
    try:
        msg = conn.test_connection()
        integration.status, integration.last_error = "ok", None
        ok = True
    except Exception as exc:  # noqa: BLE001 - surfaced to the admin, sanitized
        msg = _sanitize(exc)
        integration.status, integration.last_error = "error", msg
        ok = False
    finally:
        conn.close()
    integration.last_test_at = utcnow()
    return ok, msg


def check(
    db: Session,
    integration: Integration,
    cve_id: str,
    settings: Settings,
    *,
    force: bool = False,
    enricher: Connector | None = None,
) -> IntegrationCveCheck:
    existing = db.scalar(
        select(IntegrationCveCheck).where(
            IntegrationCveCheck.integration_id == integration.id, IntegrationCveCheck.cve_id == cve_id
        )
    )
    fresh = timedelta(minutes=settings.connector_cache_minutes)
    if existing and not force and existing.status == "ok" and as_utc(existing.checked_at) > utcnow() - fresh:
        return existing
    chk = existing or IntegrationCveCheck(integration_id=integration.id, cve_id=cve_id)
    conn = build(integration, settings, db)
    rows: list[dict[str, Any]] = []
    truncated = False
    try:
        for raw in conn.iter_findings(cve_id):
            if len(rows) >= settings.connector_max_assets:
                truncated = True
                break
            rec = map_record(raw, conn.field_map)
            if rec["hostname"] or rec["ip_address"] or rec["resource_id"]:
                rows.append(rec)
        chk.status, chk.error = "ok", None
    except UnsupportedError as exc:
        chk.status, chk.error = "unsupported", str(exc)
    except Exception as exc:  # noqa: BLE001 - per-integration isolation: one failing tool never blocks others
        chk.status, chk.error = "error", _sanitize(exc)
        log.warning("connector_check_failed", integration=integration.name, cve=cve_id, error=chk.error)
    finally:
        conn.close()
    if chk.status == "ok":
        if enricher is not None:
            _enrich(rows, enricher)
        db.execute(
            delete(AssetFinding).where(AssetFinding.integration_id == integration.id, AssetFinding.cve_id == cve_id)
        )
        for r in rows:
            db.add(AssetFinding(integration_id=integration.id, cve_id=cve_id, **r))
        integration.last_sync_at, integration.status = utcnow(), "ok"
    else:
        integration.last_error = chk.error
    chk.checked_at, chk.asset_count, chk.truncated = utcnow(), len(rows), truncated
    if existing is None:
        db.add(chk)
    db.flush()
    return chk


def _enrich(rows: list[dict[str, Any]], enricher: Connector) -> None:
    """Fill owner / business unit / environment from the CMDB where the source tool did not provide them."""
    cache: dict[tuple, dict | None] = {}
    looked = 0
    for r in rows:
        if r.get("owner") and r.get("business_unit") and r.get("environment"):
            continue
        key = (r.get("hostname"), r.get("ip_address"))
        if key not in cache:
            if looked >= ENRICH_LIMIT:
                break
            looked += 1
            try:
                raw = enricher.fetch_asset_details(hostname=r.get("hostname"), ip=r.get("ip_address"))
            except Exception:  # noqa: BLE001 - enrichment is best-effort
                raw = None
            cache[key] = map_record(raw, enricher.field_map) if raw else None
        ci = cache[key]
        if ci:
            for f in ("owner", "business_unit", "environment"):
                r[f] = r.get(f) or ci.get(f)


def _enricher(db: Session, settings: Settings) -> tuple[Connector | None, Integration | None]:
    for i in db.scalars(
        select(Integration).where(Integration.enabled.is_(True), Integration.kind == "servicenow_cmdb")
    ):
        if i.config.get("enrich", True):
            return build(i, settings, db), i
    return None, None


def asset_sources(db: Session) -> list[Integration]:
    """Enabled integrations that answer "which assets does this CVE affect?" (not ticketing/chat)."""
    rows = db.scalars(select(Integration).where(Integration.enabled.is_(True)).order_by(Integration.id))
    return [i for i in rows if i.kind in REGISTRY and "assets_for_cve" in REGISTRY[i.kind].spec.capabilities]


def check_all(
    db: Session, cve_id: str, settings: Settings, *, force: bool = False
) -> list[tuple[Integration, IntegrationCveCheck]]:
    integrations = asset_sources(db)
    enricher, enricher_row = _enricher(db, settings)
    try:
        results = [
            (
                i,
                check(
                    db,
                    i,
                    cve_id,
                    settings,
                    force=force,
                    enricher=enricher if enricher_row is not None and i.id != enricher_row.id else None,
                ),
            )
            for i in integrations
        ]
    finally:
        if enricher:
            enricher.close()
    db.commit()
    return results


def panel(db: Session, cve_id: str) -> dict[str, Any]:
    integrations = asset_sources(db)
    checks = {
        c.integration_id: c for c in db.scalars(select(IntegrationCveCheck).where(IntegrationCveCheck.cve_id == cve_id))
    }
    findings = list(db.scalars(select(AssetFinding).where(AssetFinding.cve_id == cve_id)))
    by_int: dict[int, list[AssetFinding]] = {}
    for f in findings:
        by_int.setdefault(f.integration_id, []).append(f)
    sources = []
    for i in integrations:
        c = checks.get(i.id)
        sources.append(
            {
                "integration_id": i.id,
                "name": i.name,
                "source": REGISTRY[i.kind].spec.label,
                "checked_at": c.checked_at if c else None,
                "status": c.status if c else "never",
                "error": c.error if c else None,
                "asset_count": c.asset_count if c else 0,
                "truncated": c.truncated if c else False,
            }
        )
    from exposurecatalyst.advisories.service import dedupe_assets

    pseudo = [
        AdvisoryAsset(
            source=REGISTRY[next(i.kind for i in integrations if i.id == f.integration_id)].spec.label,
            hostname=f.hostname,
            ip_address=f.ip_address,
            resource_id=f.resource_id,
            os=f.os,
            owner=f.owner,
            business_unit=f.business_unit,
            environment=f.environment,
            cloud_account=f.cloud_account,
            detection_date=f.detection_date,
            source_ref=f.source_ref,
            is_manual=False,
        )
        for f in findings
        if f.integration_id in {i.id for i in integrations}
    ]
    unique = dedupe_assets(pseudo)
    return {
        "integrations_configured": bool(integrations),
        "sources": sources,
        "total_unique_assets": len(unique),
        "assets": unique[:500],
        "message": ""
        if integrations
        else "No asset-source integrations configured. An admin can add vulnerability, exposure and "
        "cloud security tools under Settings → Integrations.",
    }


def integrated_tools(db: Session) -> list[tuple[str, str]]:
    """(matrix label, default detection method) of every enabled asset-source integration, in order."""
    from exposurecatalyst.advisories.service import default_method

    out: dict[str, str] = {}
    for i in asset_sources(db):
        spec = REGISTRY[i.kind].spec
        out.setdefault(spec.label, default_method(spec.category))
    return list(out.items())


def pull_into_advisory(db: Session, adv: Advisory, settings: Settings, *, force: bool = False) -> list[dict[str, Any]]:
    """Replace the advisory's integration-sourced assets with current findings; mark checked sources."""
    from exposurecatalyst.advisories.service import default_method

    results = check_all(db, adv.cve_id, settings, force=force)
    adv.assets[:] = [a for a in adv.assets if a.is_manual]
    summary = []
    for integ, chk in results:
        label = REGISTRY[integ.kind].spec.label
        st = next((s for s in adv.sources if s.source == label), None)
        if st is None:  # a newly enabled integration joins the matrix; the analyst's hide/show choice is kept
            st = AdvisorySourceStatus(source=label, integrated=False, shown=True)
            adv.sources.append(st)
        if st.detection_method is None:
            st.detection_method = default_method(REGISTRY[integ.kind].spec.category)
        if chk.status == "ok":
            st.integrated, st.last_checked = True, chk.checked_at
            for f in db.scalars(
                select(AssetFinding).where(AssetFinding.integration_id == integ.id, AssetFinding.cve_id == adv.cve_id)
            ):
                adv.assets.append(
                    AdvisoryAsset(
                        source=label,
                        is_manual=False,
                        hostname=f.hostname,
                        ip_address=f.ip_address,
                        os=f.os,
                        cloud_account=f.cloud_account,
                        resource_id=f.resource_id,
                        owner=f.owner,
                        business_unit=f.business_unit,
                        environment=f.environment,
                        detection_date=f.detection_date,
                        source_ref=f.source_ref,
                        detection_method=st.detection_method,
                    )
                )
        summary.append(
            {
                "integration": integ.name,
                "source": label,
                "status": chk.status,
                "assets": chk.asset_count,
                "truncated": chk.truncated,
                "error": chk.error,
            }
        )
    db.flush()
    return summary

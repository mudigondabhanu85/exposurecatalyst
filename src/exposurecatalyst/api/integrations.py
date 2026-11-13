"""Settings → Integrations, and CVE / advisory correlation endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.connectors import REGISTRY
from exposurecatalyst.connectors import service as corr
from exposurecatalyst.connectors.base import NORMALIZED_FIELDS, validate_base_url
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.normalize import CVE_ID_RE
from exposurecatalyst.models import Advisory, Integration
from exposurecatalyst.models.advisory import DRAFT
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P
from exposurecatalyst.security.ssrf import UnsafeURLError

router = APIRouter(prefix="/api", tags=["integrations"])


class IntegrationOut(BaseModel):
    id: int
    kind: str
    label: str
    name: str
    enabled: bool
    base_url: str
    config: dict[str, Any]
    secrets_set: list[str]
    status: str
    last_test_at: datetime | None
    last_sync_at: datetime | None
    last_error: str | None


def _out(i: Integration) -> IntegrationOut:
    secrets = corr.load_secrets(i)
    return IntegrationOut(
        id=i.id,
        kind=i.kind,
        label=REGISTRY[i.kind].spec.label,
        name=i.name,
        enabled=i.enabled,
        base_url=i.base_url,
        config=i.config or {},
        secrets_set=sorted(k for k, v in secrets.items() if v),
        status=i.status,
        last_test_at=i.last_test_at,
        last_sync_at=i.last_sync_at,
        last_error=i.last_error,
    )


class IntegrationIn(BaseModel):
    kind: str
    name: str = Field(min_length=2, max_length=100)
    base_url: str = Field(min_length=8, max_length=500)
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def known(cls, v: str) -> str:
        if v not in REGISTRY:
            raise ValueError(f"unknown connector kind '{v}'")
        return v


class IntegrationPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=100)
    base_url: str | None = Field(None, min_length=8, max_length=500)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = Field(None, description="Only keys present are changed; empty string clears")


def _clean_config(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    spec = REGISTRY[kind].spec
    allowed = {f.key: f for f in spec.fields if f.kind != "secret"}
    out: dict[str, Any] = {}
    for k, v in config.items():
        if k == "field_map":
            if not isinstance(v, dict) or not set(v) <= set(NORMALIZED_FIELDS):
                raise HTTPException(422, f"field_map keys must be among {', '.join(NORMALIZED_FIELDS)}")
            out[k] = {fk: str(fv)[:200] for fk, fv in v.items() if fv}
            continue
        f = allowed.get(k)
        if f is None:
            raise HTTPException(422, f"unknown setting '{k}' for {spec.vendor}")
        if f.kind == "select" and v not in f.options:
            raise HTTPException(422, f"{f.label} must be one of {', '.join(f.options)}")
        if f.kind == "number":
            try:
                v = int(v)
            except (TypeError, ValueError) as exc:
                raise HTTPException(422, f"{f.label} must be a number") from exc
        if f.kind == "bool":
            v = bool(v)
        out[k] = v if f.kind in ("number", "bool") else str(v)[:500]
    return out


def _check_secrets(kind: str, secrets: dict[str, str]) -> dict[str, str]:
    keys = {f.key for f in REGISTRY[kind].spec.fields if f.kind == "secret"}
    unknown = set(secrets) - keys
    if unknown:
        raise HTTPException(422, f"unknown secret(s): {', '.join(sorted(unknown))}")
    return {k: v[:4096] for k, v in secrets.items()}


def _validate_url(kind: str, url: str, settings: Settings) -> str:
    try:
        return validate_base_url(kind, url.strip(), settings)
    except UnsafeURLError as exc:
        raise HTTPException(422, f"Base URL rejected: {exc}") from exc


@router.get("/integrations/catalog")
def catalog(_: Principal = Depends(require(P.INTEGRATION_MANAGE))) -> list[dict[str, Any]]:
    return [cls.spec.public() for cls in sorted(REGISTRY.values(), key=lambda c: c.spec.label)]


@router.get("/integrations", response_model=list[IntegrationOut])
def list_integrations(_: Principal = Depends(require(P.INTEGRATION_MANAGE)), db: Session = Depends(get_db)):
    return [_out(i) for i in db.scalars(select(Integration).order_by(Integration.name))]


@router.post("/integrations", response_model=IntegrationOut, status_code=201)
def create_integration(
    body: IntegrationIn,
    request: Request,
    p: Principal = Depends(require(P.INTEGRATION_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> IntegrationOut:
    if db.scalar(select(Integration).where(func.lower(Integration.name) == body.name.strip().lower())):
        raise HTTPException(409, "An integration with that name exists")
    i = Integration(
        kind=body.kind,
        name=body.name.strip(),
        enabled=body.enabled,
        created_by=p.user.id,
        state={},
        base_url=_validate_url(body.kind, body.base_url, settings),
        config=_clean_config(body.kind, body.config),
    )
    corr.store_secrets(i, _check_secrets(body.kind, body.secrets))
    db.add(i)
    db.flush()
    audit.record(
        db,
        "integration.created",
        actor=p.user,
        request=request,
        target_type="integration",
        target_id=i.id,
        details={"kind": i.kind, "name": i.name, "base_url": i.base_url, "secrets_set": sorted(body.secrets)},
    )
    db.commit()
    return _out(i)


def _get(db: Session, integration_id: int) -> Integration:
    i = db.get(Integration, integration_id)
    if i is None:
        raise HTTPException(404, "Integration not found")
    return i


@router.patch("/integrations/{integration_id}", response_model=IntegrationOut)
def update_integration(
    integration_id: int,
    body: IntegrationPatch,
    request: Request,
    p: Principal = Depends(require(P.INTEGRATION_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> IntegrationOut:
    i = _get(db, integration_id)
    changed: dict[str, Any] = {}
    if body.name is not None:
        i.name = changed["name"] = body.name.strip()
    if body.base_url is not None:
        i.base_url = changed["base_url"] = _validate_url(i.kind, body.base_url, settings)
        i.status = "never"  # a new endpoint must be re-tested
    if body.config is not None:
        i.config = _clean_config(i.kind, {**(i.config or {}), **body.config})
        changed["config"] = i.config
    if body.secrets is not None:
        merged = {**corr.load_secrets(i), **_check_secrets(i.kind, body.secrets)}
        corr.store_secrets(i, {k: v for k, v in merged.items() if v})
        changed["secrets_changed"] = sorted(body.secrets)
        i.status = "never"
    if body.enabled is not None:
        i.enabled = changed["enabled"] = body.enabled
    audit.record(
        db,
        "integration.updated",
        actor=p.user,
        request=request,
        target_type="integration",
        target_id=i.id,
        details=changed,
    )
    db.commit()
    return _out(i)


@router.delete("/integrations/{integration_id}", status_code=204)
def delete_integration(
    integration_id: int,
    request: Request,
    p: Principal = Depends(require(P.INTEGRATION_MANAGE)),
    db: Session = Depends(get_db),
) -> None:
    i = _get(db, integration_id)
    audit.record(
        db,
        "integration.deleted",
        actor=p.user,
        request=request,
        target_type="integration",
        target_id=i.id,
        details={"name": i.name, "kind": i.kind},
    )
    db.delete(i)
    db.commit()


@router.post("/integrations/{integration_id}/test")
def test_integration(
    integration_id: int,
    request: Request,
    p: Principal = Depends(require(P.INTEGRATION_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict[str, Any]:
    i = _get(db, integration_id)
    ok, message = corr.test(db, i, settings)
    audit.record(
        db,
        "integration.tested",
        actor=p.user,
        request=request,
        target_type="integration",
        target_id=i.id,
        outcome="success" if ok else "failure",
        details={"message": message[:200]},
    )
    db.commit()
    return {"ok": ok, "message": message, "integration": _out(i).model_dump(mode="json")}


# ---- correlation ---------------------------------------------------------------------------------


def _cve(cve_id: str) -> str:
    cve_id = cve_id.upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(422, "Invalid CVE ID")
    return cve_id


@router.get("/cves/{cve_id}/assets")
def cve_assets(cve_id: str, _: Principal = Depends(require(P.CVE_VIEW)), db: Session = Depends(get_db)) -> dict:
    return corr.panel(db, _cve(cve_id))


@router.post("/cves/{cve_id}/assets/refresh")
def refresh_cve_assets(
    cve_id: str,
    request: Request,
    p: Principal = Depends(require(P.CVE_REFRESH)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    cve_id = _cve(cve_id)
    results = corr.check_all(db, cve_id, settings, force=True)
    audit.record(
        db,
        "cve.assets_checked",
        actor=p.user,
        request=request,
        target_type="cve",
        target_id=cve_id,
        details={"integrations": [{"name": i.name, "status": c.status, "assets": c.asset_count} for i, c in results]},
    )
    db.commit()
    return corr.panel(db, cve_id)


class PullIn(BaseModel):
    force: bool = False


@router.post("/advisories/{advisory_pk}/assets/pull")
def pull_assets(
    advisory_pk: int,
    body: PullIn,
    request: Request,
    p: Principal = Depends(require(P.ADVISORY_CREATE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    from exposurecatalyst.api.advisories import _out as advisory_out

    adv = db.get(Advisory, advisory_pk)
    if adv is None:
        raise HTTPException(404, "Advisory not found")
    if adv.status != DRAFT:
        raise HTTPException(409, f"advisory is '{adv.status}'; this action needs: draft")
    summary = corr.pull_into_advisory(db, adv, settings, force=body.force)
    audit.record(
        db,
        "advisory.assets_pulled",
        actor=p.user,
        request=request,
        target_type="advisory",
        target_id=adv.advisory_id,
        details={"results": summary},
    )
    db.commit()
    return {"results": summary, "advisory": advisory_out(db, adv).model_dump(mode="json")}

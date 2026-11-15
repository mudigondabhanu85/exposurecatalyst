"""Deployment information and admin banners (domain changed, self-signed / expiring certificate)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from exposurecatalyst import __version__, deployment
from exposurecatalyst.api.deps import Principal, current_principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/banners")
def get_banners(p: Principal = Depends(current_principal), db: Session = Depends(get_db),
                settings: Settings = Depends(settings_dep)) -> list[dict[str, Any]]:
    return deployment.banners(db, settings, admin=str(P.SETTINGS_MANAGE) in p.permissions)


@router.post("/banners/{banner_id}/dismiss", status_code=204)
def dismiss_banner(banner_id: str, request: Request, p: Principal = Depends(require(P.SETTINGS_MANAGE)),
                   db: Session = Depends(get_db)) -> None:
    if not deployment.dismiss(db, banner_id):
        raise HTTPException(404, "Banner not found or not dismissible")
    audit.record(db, "system.banner_dismissed", actor=p.user, request=request, target_type="banner",
                 target_id=banner_id)
    db.commit()


@router.get("/deployment")
def deployment_info(_: Principal = Depends(require(P.SETTINGS_MANAGE)),
                    settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    return {
        "version": __version__,
        "deployment": settings.deployment,
        "fqdn": settings.fqdn,
        "public_url": settings.public_url,
        "explicit_public_url": settings.explicit_public_url,
        "https_port": settings.https_port or 443,
        "tls_mode": settings.tls_mode,
        "hsts": settings.hsts_enabled,
        "allowed_hosts": settings.allowed_hosts,
        "urls": deployment.derived_urls(settings),
        "certificate": deployment.certificate_status(settings),
        "features": settings.features.model_dump(),
    }

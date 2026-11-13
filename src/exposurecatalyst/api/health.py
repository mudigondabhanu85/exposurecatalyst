from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from exposurecatalyst import __version__
from exposurecatalyst.db.session import get_db

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("/live")
def live() -> dict:
    return {"status": "ok", "version": __version__}


@router.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - never leak DB errors to unauthenticated callers
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    return {"status": "ok", "database": "up", "version": __version__}

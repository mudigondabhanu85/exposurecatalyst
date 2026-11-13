from __future__ import annotations

from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from exposurecatalyst.api.deps import Principal, current_principal
from exposurecatalyst.config import get_settings
from exposurecatalyst.help import HelpRepository

router = APIRouter(prefix="/api/help", tags=["help"])


@lru_cache
def repo() -> HelpRepository:
    return HelpRepository(get_settings().help_dir)


@router.get("")
def index(p: Principal = Depends(current_principal)) -> list[dict]:
    return [{"id": h.id, "title": h.title, "summary": h.summary, "page": h.page, "docs": h.docs}
            for h in repo().visible(p.permissions)]


@router.get("/search")
def search(q: str = Query(..., min_length=2, max_length=100), p: Principal = Depends(current_principal)) -> list:
    return repo().search(q, p.permissions)


@router.get("/tooltips")
def tooltips(_: Principal = Depends(current_principal)) -> dict:
    return repo().tooltips()


@router.get("/changelog", response_class=PlainTextResponse)
def changelog(_: Principal = Depends(current_principal)) -> str:
    path = get_settings().changelog_path
    return path.read_text(encoding="utf-8") if path.exists() else "No changelog available."


@router.get("/pages/{page_id}")
def page(page_id: str, p: Principal = Depends(current_principal)) -> dict:
    h = repo().get(page_id, p.permissions)
    if h is None:
        raise HTTPException(404, "Help topic not found")
    return repo().render(h, p.permissions)

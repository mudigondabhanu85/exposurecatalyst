from __future__ import annotations

import json
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse

from exposurecatalyst.api.deps import Principal, current_principal
from exposurecatalyst.config import get_settings
from exposurecatalyst.docs.guides import FORMATS, GUIDES, GUIDES_BY_ID, export_filename
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


def _manifest() -> dict:
    path = get_settings().docs_exports_dir / "manifest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@router.get("/downloads")
def downloads(p: Principal = Depends(current_principal)) -> dict:
    """Documentation exports this user may download (guides are filtered by role)."""
    manifest = _manifest()
    built = {g["id"]: g.get("files", {}) for g in manifest.get("guides", [])}
    guides = []
    for g in GUIDES:
        if g.id not in built or not g.allowed(p.permissions):
            continue
        files = [{"format": fmt, "size": built[g.id][fmt]["size"], "url": f"/api/help/downloads/{g.id}/{fmt}"}
                 for fmt in FORMATS if fmt in built[g.id]]
        guides.append({"id": g.id, "title": g.title, "description": g.description, "files": files})
    return {"version": manifest.get("version"), "date": manifest.get("date"),
            "classification": manifest.get("classification"), "guides": guides}


@router.get("/downloads/{guide_id}/{fmt}")
def download(guide_id: str, fmt: str, p: Principal = Depends(current_principal)) -> FileResponse:
    guide = GUIDES_BY_ID.get(guide_id)
    if guide is None or fmt not in FORMATS or not guide.allowed(p.permissions):
        raise HTTPException(404, "Document not found")
    path = get_settings().docs_exports_dir / export_filename(guide.id, fmt)
    if not path.is_file():
        raise HTTPException(404, "Document not built — run `python -m exposurecatalyst.docs build`")
    # Always an attachment: the standalone HTML must never render inside the application origin.
    return FileResponse(path, media_type=FORMATS[fmt], filename=path.name, content_disposition_type="attachment")

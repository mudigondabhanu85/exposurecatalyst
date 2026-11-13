from __future__ import annotations

import html
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import inspect

from exposurecatalyst import __version__
from exposurecatalyst.api import admin, auth, cves, health, help, sources
from exposurecatalyst.config import Settings, get_settings
from exposurecatalyst.db.session import get_engine, get_session_factory, init_engine, session_scope
from exposurecatalyst.ingestion.service import ensure_source_states
from exposurecatalyst.logging import configure_logging
from exposurecatalyst.security.middleware import (
    OriginCheckMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from exposurecatalyst.security.rbac import seed_roles
from exposurecatalyst.security.sessions import cookie_names, resolve_session

log = structlog.get_logger(__name__)


def bootstrap(settings: Settings) -> None:
    """Seed system roles and source rows once the schema exists (migrations own the schema)."""
    if not inspect(get_engine()).has_table("roles"):
        log.warning("schema_missing", hint="run `exposurecatalyst migrate`")
        return
    with session_scope() as db:
        seed_roles(db)
        ensure_source_states(db)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)
    init_engine(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        bootstrap(settings)
        scheduler = None
        if settings.scheduler_embedded:
            from exposurecatalyst.ingestion.scheduler import start_background

            scheduler = start_background(settings)
        yield
        if scheduler:
            scheduler.shutdown(wait=False)

    app = FastAPI(
        title="ExposureCatalyst API",
        version=__version__,
        description="Vulnerability Intelligence & Advisory Platform. Authenticate via `POST /api/auth/login`; "
        "send the `X-CSRF-Token` header (value from `/api/auth/me`) on every state-changing request.",
        docs_url=None,  # branded Swagger/ReDoc routes registered below
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.api_docs_enabled else None,
        lifespan=lifespan,
    )
    # Starlette runs the last-added middleware first.
    app.add_middleware(OriginCheckMiddleware, settings=settings)
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware)
    if settings.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True,
                           allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                           allow_headers=["Content-Type", "X-CSRF-Token"])

    for r in (health.router, auth.router, cves.router, sources.router, help.router, admin.router):
        app.include_router(r)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # never leak stack traces to clients
        log.exception("unhandled_error", path=request.url.path)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    if settings.api_docs_enabled:
        from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html

        @app.get("/api/docs", include_in_schema=False)
        def swagger_ui():
            return get_swagger_ui_html(openapi_url="/api/openapi.json", title="ExposureCatalyst API",
                                       swagger_favicon_url="/brand/favicon/favicon.svg")

        @app.get("/api/redoc", include_in_schema=False)
        def redoc():
            return get_redoc_html(openapi_url="/api/openapi.json", title="ExposureCatalyst API",
                                  redoc_favicon_url="/brand/favicon/favicon.svg", with_google_fonts=False)

    if settings.metrics_enabled:

        @app.get("/metrics", include_in_schema=False)
        def metrics() -> Response:
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.middleware("http")
    async def docs_require_login(request: Request, call_next):
        # Architecture/security docs describe internal topology — authenticated users only.
        if request.url.path == "/docs" or request.url.path.startswith("/docs/"):
            token = request.cookies.get(cookie_names(settings)[0])
            with get_session_factory()() as db:
                ok = resolve_session(db, token, settings) is not None
            if not ok:
                return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
        return await call_next(request)

    if settings.docs_site_dir.is_dir():
        app.mount("/docs", StaticFiles(directory=settings.docs_site_dir, html=True), name="docs")
    _mount_spa(app, settings.frontend_dist_dir, settings.public_url.rstrip("/"))
    return app


MEDIA_TYPES = {".webmanifest": "application/manifest+json", ".svg": "image/svg+xml", ".ico": "image/x-icon"}


def _mount_spa(app: FastAPI, dist: Path, public_url: str) -> None:
    index = dist / "index.html"
    index_html: str | None = None

    def render_index() -> HTMLResponse:
        nonlocal index_html
        if index_html is None:  # absolute URLs for Open Graph / Twitter link previews
            index_html = index.read_text(encoding="utf-8").replace("__EXCAT_PUBLIC_URL__", html.escape(public_url))
        return HTMLResponse(index_html)
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
    if (dist / "brand").is_dir():
        app.mount("/brand", StaticFiles(directory=dist / "brand"), name="brand")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith(("api/", "docs/", "metrics")):
            raise HTTPException(404, "Not found")
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and dist.resolve() in candidate.parents:
            return FileResponse(candidate, media_type=MEDIA_TYPES.get(candidate.suffix))
        if index.exists():
            return render_index()
        return JSONResponse({"detail": "Frontend not built. Run `make frontend`."}, status_code=404)


def app_factory() -> FastAPI:  # uvicorn --factory entry point
    return create_app()

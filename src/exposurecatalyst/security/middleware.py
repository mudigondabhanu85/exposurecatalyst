from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from threading import Lock

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from exposurecatalyst.config import Settings

log = structlog.get_logger("http")

# The React app ships no inline script/style, so the app CSP needs no 'unsafe-inline'.
APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)
# MkDocs Material and Swagger UI use inline bootstrap scripts; scoped to their paths only (ADR-0005).
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; "
    "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Settings):
        super().__init__(app)
        self.hsts = settings.cookie_secure
        # Only ask browsers to upgrade sub-resources when the app is actually served over HTTPS;
        # on plain-HTTP local runs it would break loading of the SPA's own assets.
        self.app_csp = APP_CSP + ("; upgrade-insecure-requests" if settings.public_url.startswith("https://") else "")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        path = request.url.path
        loose = path.startswith("/docs") or path in ("/api/docs", "/api/redoc")
        response.headers["Content-Security-Policy"] = DOCS_CSP if loose else self.app_csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        if self.hsts:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(request_id=request_id)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
        response.headers["X-Request-ID"] = request_id
        log.info(
            "request",
            method=request.method,
            path=request.url.path,  # never the query string: may contain search terms
            status=response.status_code,
            ms=round((time.perf_counter() - start) * 1000, 1),
            request_id=request_id,
        )
        return response


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Reject cross-origin state-changing requests (defence in depth with CSRF tokens)."""

    def __init__(self, app: ASGIApp, settings: Settings):
        super().__init__(app)
        self.allowed = settings.allowed_origins

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and origin not in self.allowed:
                return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
        return await call_next(request)


class SlidingWindowLimiter:
    """In-process limiter. Multi-node deployments should front this with WAF rate rules (AWS WAF)."""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

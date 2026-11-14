"""Outbound HTTP for sources: SSRF guard, rate limiting, retries with exponential backoff + jitter."""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin

import httpx
import structlog

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.security.ssrf import validate_outbound_url

log = structlog.get_logger(__name__)
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
REDIRECT_STATUS = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 3


class SourceHTTPError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class RateLimiter:
    """Token bucket: ``rate`` requests per ``per`` seconds (thread-safe)."""

    def __init__(self, rate: int, per: float, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.capacity = float(rate)
        self.tokens = float(rate)
        self.fill_rate = rate / per
        self.clock, self.sleep = clock, sleep
        self.updated = clock()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            while True:
                now = self.clock()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.fill_rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                self.sleep((1 - self.tokens) / self.fill_rate)


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            return max(0.0, (parsedate_to_datetime(value) - utcnow()).total_seconds())
        except (TypeError, ValueError):
            return None


class SourceClient:
    def __init__(
        self,
        name: str,
        settings: Settings,
        *,
        rate: int,
        per: float,
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        allowlist: list[str] | None = None,
        timeout: float | None = None,
    ):
        self.name = name
        self.settings = settings
        # Hosts this client may call: an explicit list (connectors) or the global egress allowlist.
        self.allowlist = allowlist if allowlist is not None else settings.egress_allowlist_list
        self.sleep = sleep
        self.limiter = RateLimiter(rate, per, sleep=sleep)
        self.retry_status = set(RETRY_STATUS)  # connectors may add vendor-specific throttling codes
        self.client = httpx.Client(
            timeout=timeout or settings.http_timeout_seconds,
            headers={"User-Agent": settings.http_user_agent, **(headers or {})},
            transport=transport,
            follow_redirects=False,  # redirects could bypass the SSRF allowlist
        )

    def close(self) -> None:
        self.client.close()

    def _backoff(self, attempt: int) -> float:
        base = self.settings.http_backoff_base_seconds * (2**attempt)
        return min(self.settings.http_backoff_max_seconds, base) * (0.5 + random.random() / 2)  # noqa: S311  # nosec B311

    def get(self, url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None,
            ok_statuses: tuple[int, ...] = (200,)) -> httpx.Response:
        """GET with retries. Redirects are followed manually (≤3 hops) and every hop is re-validated
        against the SSRF guard and egress allowlist, so a redirect can never reach a blocked host."""
        for _hop in range(MAX_REDIRECTS + 1):
            resp = self.request("GET", url, params=params, headers=headers, ok_statuses=ok_statuses)
            if resp.status_code not in REDIRECT_STATUS or resp.status_code in ok_statuses:
                return resp
            location = resp.headers.get("location")
            if not location:
                raise SourceHTTPError(f"{self.name}: HTTP {resp.status_code} without Location")
            url, params = urljoin(str(resp.request.url), location), None
        raise SourceHTTPError(f"{self.name}: too many redirects")

    def request(self, method: str, url: str, *, params: dict[str, Any] | None = None,
                headers: dict[str, str] | None = None, json: Any = None, data: Any = None,
                auth: httpx.Auth | tuple[str, str] | None = None,
                ok_statuses: tuple[int, ...] = (200,)) -> httpx.Response:
        """One request with retries (429/5xx/transport errors). Redirect responses are returned as-is:
        only GET follows them (see ``get``); for other methods a redirect is an error."""
        validate_outbound_url(
            url,
            allowlist=self.allowlist,
            allow_private=self.settings.ssrf_allow_private_networks,
            resolve_dns=self.settings.ssrf_resolve_dns,
        )
        retries = self.settings.http_max_retries
        last_error = "unknown error"
        for attempt in range(retries + 1):
            self.limiter.acquire()
            try:
                resp = self.client.request(method, url, params=params, headers=headers, json=json, data=data,
                                           auth=auth)
            except httpx.TransportError as exc:
                last_error = f"{type(exc).__name__}"
                delay = self._backoff(attempt)
            else:
                if resp.status_code in ok_statuses or (method == "GET" and resp.status_code in REDIRECT_STATUS):
                    return resp
                if resp.status_code not in self.retry_status:
                    raise SourceHTTPError(f"{self.name}: HTTP {resp.status_code} from {url.split('?')[0]}",
                                          status=resp.status_code)
                last_error = f"HTTP {resp.status_code}"
                delay = _retry_after(resp) or self._backoff(attempt)
            if attempt < retries:
                delay = min(delay, self.settings.http_backoff_max_seconds)
                log.warning("source_http_retry", source=self.name, attempt=attempt + 1, delay=round(delay, 1),
                            error=last_error)
                self.sleep(delay)
        raise SourceHTTPError(f"{self.name}: giving up after {retries + 1} attempts ({last_error})")

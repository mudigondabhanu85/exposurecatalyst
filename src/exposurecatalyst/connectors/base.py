"""Connector plugin interface.

A connector turns "which assets are affected by CVE-X?" into vendor API calls and yields *raw* records.
The framework maps raw records to the normalized asset model through a per-connector default field map
that admins can override per integration (Settings → Integrations → Field mapping).

Adding a tool = subclass ``Connector``, declare a ``ConnectorSpec``, decorate with ``@register``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx

from exposurecatalyst.config import Settings
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.models import Integration
from exposurecatalyst.security.ssrf import UnsafeURLError, host_matches, validate_outbound_url

NORMALIZED_FIELDS = (
    "hostname",
    "ip_address",
    "os",
    "cloud_account",
    "resource_id",
    "owner",
    "business_unit",
    "environment",
    "detection_date",
    "source_ref",
)
LIMITS = {
    "hostname": 255,
    "ip_address": 64,
    "os": 128,
    "cloud_account": 128,
    "resource_id": 512,
    "owner": 200,
    "business_unit": 200,
    "environment": 64,
    "source_ref": 128,
}


class ConnectorError(RuntimeError):
    """Expected, user-actionable failure (bad credentials, missing scope, unsupported feature)."""


class UnsupportedError(ConnectorError):
    """The integration cannot answer CVE questions (e.g. ServiceNow without Vulnerability Response)."""


@dataclass(frozen=True)
class ConfigField:
    key: str
    label: str
    kind: str = "text"  # text | url | secret | number | bool | select
    required: bool = False
    default: Any = None
    help: str = ""
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConnectorSpec:
    kind: str
    label: str  # row name in the advisory validation matrix
    vendor: str
    description: str
    host_patterns: tuple[str, ...]  # SaaS hosts allowed for base_url (plus the global egress allowlist)
    base_url_example: str
    fields: tuple[ConfigField, ...]
    default_field_map: dict[str, str]
    prerequisites: tuple[str, ...]
    docs: str
    rate: tuple[int, float] = (60, 60.0)  # requests per seconds
    capabilities: tuple[str, ...] = ("assets_for_cve",)
    category: str = "Vulnerability & exposure"  # catalog grouping in the UI
    regions: tuple[tuple[str, str], ...] = ()  # (label, base URL) choices offered in the setup form
    # "documented": request/response shapes follow the vendor's public API reference.
    # "confirm": endpoint/filter defaults follow the vendor's usual pattern but its reference is not public —
    # confirm them against your tenant's API docs (they are all editable settings).
    api_status: str = "documented"
    auth_hosts: tuple[str, ...] = ()  # token endpoints on another host (allowed for egress, not as base URL)
    fixed_base_url: str | None = None  # connectors without a per-tenant URL (Slack, Teams): form hides the field

    def public(self) -> dict[str, Any]:
        d = asdict(self)
        d["fields"] = [asdict(f) for f in self.fields]
        return d


def get_path(obj: Any, path: str, *, join: bool = True) -> Any:
    """Dotted-path lookup: 'vulnerableAsset.ipAddresses.0'. Lists without an index are joined."""
    if path.startswith("="):  # literal constant, e.g. "=Production"
        return path[1:]
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, list):
            if part.isdigit():
                idx = int(part)
                cur = cur[idx] if idx < len(cur) else None
                continue
            cur = [c.get(part) if isinstance(c, dict) else None for c in cur]
            continue
        cur = cur.get(part) if isinstance(cur, dict) else None
    if join and isinstance(cur, list):
        cur = ", ".join(str(c) for c in cur if c not in (None, ""))
    return cur


def _to_date(v: Any) -> date | None:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
        n = float(v)
        if n <= 0:
            return None
        if n > 1e11:  # epoch milliseconds
            n /= 1000
        try:
            return datetime.fromtimestamp(n, tz=UTC).date()
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(s[:10])
        except ValueError:
            return None


def map_record(raw: dict[str, Any], field_map: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for fld in NORMALIZED_FIELDS:
        path = field_map.get(fld)
        if not path:
            out[fld] = None
            continue
        value = get_path(raw, path)
        if fld == "detection_date":
            out[fld] = _to_date(value)
        else:
            out[fld] = str(value).strip()[: LIMITS[fld]] if value not in (None, "") else None
    return out


class Connector(ABC):
    spec: ClassVar[ConnectorSpec]

    def __init__(
        self,
        integration: Integration,
        secrets: dict[str, str],
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ):
        self.integration = integration
        self.secrets = secrets
        self.settings = settings
        self.config = {f.key: integration.config.get(f.key, f.default) for f in self.spec.fields if f.kind != "secret"}
        self.base_url = integration.base_url.rstrip("/")
        rate, per = self.spec.rate
        self.client = SourceClient(
            f"{self.spec.kind}:{integration.name}",
            settings,
            rate=rate,
            per=per,
            transport=transport,
            allowlist=[*self.spec.host_patterns, *self.spec.auth_hosts, *settings.egress_allowlist_list],
            timeout=settings.connector_timeout_seconds,
            **({"sleep": sleep} if sleep else {}),
            headers={"Accept": "application/json"},
        )

    @property
    def field_map(self) -> dict[str, str]:
        return {**self.spec.default_field_map, **(self.integration.config.get("field_map") or {})}

    def url(self, path: str) -> str:
        return self.base_url + (path if path.startswith("/") else "/" + path)

    def close(self) -> None:
        self.client.close()

    @abstractmethod
    def test_connection(self) -> str:
        """Authenticate and make one cheap read. Returns a human-readable success message."""

    @abstractmethod
    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        """Yield raw records (one per affected asset/detection) for an exact CVE ID, handling pagination."""

    def fetch_asset_details(self, *, hostname: str | None = None, ip: str | None = None) -> dict[str, Any] | None:
        """Optional enrichment lookup (owner, business unit, environment). Raw record or None."""
        return None


REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    REGISTRY[cls.spec.kind] = cls
    return cls


def validate_base_url(kind: str, url: str, settings: Settings) -> str:
    """Admin-supplied URL: https only, host must be the vendor's SaaS domain or explicitly allowlisted,
    and must not resolve to internal/metadata addresses (unless private networks are allowed globally)."""
    spec = REGISTRY[kind].spec
    host = (urlsplit(url).hostname or "").lower()
    allow = [*spec.host_patterns, *settings.egress_allowlist_list]
    if not host_matches(host, allow):
        if not spec.host_patterns:
            raise UnsafeURLError(f"{spec.vendor} is self-hosted: add '{host}' to EXCAT_EGRESS_ALLOWLIST to allow it")
        raise UnsafeURLError(
            f"host '{host}' is not a known {spec.vendor} domain "
            f"({', '.join(spec.host_patterns)}); add it to EXCAT_EGRESS_ALLOWLIST for on-prem/custom hosts"
        )
    validate_outbound_url(
        url, allowlist=allow, allow_private=settings.ssrf_allow_private_networks, resolve_dns=settings.ssrf_resolve_dns
    )
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        raise UnsafeURLError("base URL must not contain a query string or fragment")
    return url.rstrip("/")


def first(v: Any) -> Any:
    """First element of a list (vendors often return single values as one-item lists)."""
    if isinstance(v, list):
        return next((x for x in v if x not in (None, "")), None)
    return v


def flatten_keys(record: dict[str, Any]) -> dict[str, Any]:
    """Vendor records with dotted *key names* ('specific_data.data.hostname') → nested dicts, so dotted
    field-map paths resolve. Keys without dots are kept as-is."""
    nested: dict[str, Any] = {}
    for k, v in record.items():
        cur = nested
        *parents, leaf = str(k).split(".")
        for part in parents:
            nxt = cur.setdefault(part, {})
            if not isinstance(nxt, dict):
                nxt = cur[part] = {"_value": nxt}
            cur = nxt
        cur[leaf] = v
    return nested


def json_body(resp: httpx.Response, vendor: str) -> Any:
    try:
        return resp.json()
    except ValueError as exc:
        raise ConnectorError(f"{vendor} returned a non-JSON response") from exc


class ActionConnector(Connector):
    """Outbound connector (ticketing / chat) — it does not answer CVE asset questions."""

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        raise UnsupportedError(f"{self.spec.vendor} is an action connector and is not queried for assets")

    @abstractmethod
    def deliver(self, item: dict[str, Any]) -> dict[str, Any]:
        """Create a ticket / post a message for an advisory. Returns {"ref": str, "url": str | None}."""


class TokenCache:
    """Bearer token with expiry (OAuth client-credentials connectors)."""

    def __init__(self) -> None:
        self.token: str | None = None
        self.expires = 0.0

    def get(self, fetch: Callable[[], tuple[str, int]]) -> str:
        if self.token is None or time.monotonic() > self.expires - 60:
            self.token, ttl = fetch()
            self.expires = time.monotonic() + ttl
        return self.token

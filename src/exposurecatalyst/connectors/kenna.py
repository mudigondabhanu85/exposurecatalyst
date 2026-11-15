"""Cisco Vulnerability Management (Kenna) — ``GET /vulnerabilities/search`` then asset lookups.

Vulnerabilities are searched with the Kenna search-terms ``q`` parameter (default ``cve:"<CVE>"``, a setting)
and ``status[]=open``; each vulnerability's ``asset_id`` is resolved with ``GET /assets/{id}`` (cached).
Auth: ``X-Risk-Token``. Search pagination is capped by Kenna at 20 pages.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import structlog

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorSpec,
    json_body,
    register,
)

PAGE = 500
MAX_PAGES = 20
MAX_ASSET_LOOKUPS = 2000
log = structlog.get_logger(__name__)


@register
class KennaConnector(Connector):
    spec = ConnectorSpec(
        kind="kenna",
        label="Cisco Vulnerability Management",
        vendor="Cisco Vulnerability Management (Kenna)",
        description="Open vulnerabilities for the CVE and their assets from Cisco Vulnerability Management.",
        host_patterns=(
            "api.kennasecurity.com",
            "api.us.kennasecurity.com",
            "api.eu.kennasecurity.com",
            "api.ca.kennasecurity.com",
        ),
        base_url_example="https://api.kennasecurity.com",
        regions=(
            ("US", "https://api.kennasecurity.com"),
            ("EU", "https://api.eu.kennasecurity.com"),
            ("CA", "https://api.ca.kennasecurity.com"),
        ),
        fields=(
            ConfigField("api_token", "API key (X-Risk-Token)", kind="secret", required=True),
            ConfigField(
                "search_query", "Search query", default='cve:"{cve}"', help="Kenna search terms; {cve} is replaced"
            ),
        ),
        default_field_map={
            "hostname": "asset.hostname",
            "ip_address": "asset.ip_address",
            "os": "asset.operating_system",
            "resource_id": "asset.external_id",
            "owner": "asset.owner",
            "business_unit": "asset.asset_groups.name",
            "environment": "asset.tags",
            "detection_date": "first_found_on",
            "source_ref": "id",
        },
        prerequisites=(
            "API key for a read-only user (Settings → API Keys)",
            "Your region's API host (US, EU or CA)",
        ),
        docs="integrations/kenna/",
        rate=(5, 1.0),
        category="Exposure management (CTEM / RBVM)",
        api_status="confirm",
    )

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self.client.request(
            "GET", self.url(path), params=params, headers={"X-Risk-Token": self.secrets.get("api_token", "")}
        )
        return json_body(resp, "Cisco Vulnerability Management")

    def test_connection(self) -> str:
        self._get("/asset_groups", {"per_page": 1})
        return "Connected to Cisco Vulnerability Management"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        q = (self.config.get("search_query") or 'cve:"{cve}"').replace("{cve}", cve_id.replace('"', ""))
        assets: dict[Any, dict[str, Any] | None] = {}
        for page in range(1, MAX_PAGES + 1):
            data = self._get("/vulnerabilities/search", {"q": q, "status[]": "open", "per_page": PAGE, "page": page})
            vulns = data.get("vulnerabilities") or []
            for v in vulns:
                if v.get("cve_id") and str(v["cve_id"]).upper() != cve_id:
                    continue  # the search language is fuzzy; keep exact CVE matches only
                aid = v.get("asset_id")
                if aid not in assets and len(assets) < MAX_ASSET_LOOKUPS:
                    try:
                        assets[aid] = self._get(f"/assets/{int(aid)}").get("asset")
                    except (TypeError, ValueError):
                        assets[aid] = None
                v["asset"] = assets.get(aid) or {}
                yield v
            pages = int(((data.get("meta") or {}).get("pages")) or 0)
            if not vulns or page >= pages:
                return
        log.warning("kenna_search_page_cap", cve=cve_id, pages=MAX_PAGES)  # Kenna caps searches at 20 pages

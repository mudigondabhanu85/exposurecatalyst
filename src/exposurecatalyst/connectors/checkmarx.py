"""Checkmarx One — projects whose latest completed scan has an SCA result for the CVE.

Checkmarx One has no organization-wide CVE search, so the connector walks projects (``GET /api/projects``),
takes each project's last completed scan (``GET /api/projects/last-scan``) and reads its SCA results
(``GET /api/results?scan-id=…``), keeping results whose ID / CVE name equals the CVE. Bounded by
*Max projects*. Auth: API key (an OAuth refresh token) exchanged at the tenant's IAM realm.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    TokenCache,
    json_body,
    register,
)

PAGE = 100
RESULTS_PAGE = 1000
REGIONS = {
    "US": "ast.checkmarx.net",
    "US2": "us.ast.checkmarx.net",
    "EU": "eu.ast.checkmarx.net",
    "EU2": "eu-2.ast.checkmarx.net",
    "DEU": "deu.ast.checkmarx.net",
    "ANZ": "anz.ast.checkmarx.net",
    "India": "ind.ast.checkmarx.net",
    "Singapore": "sng.ast.checkmarx.net",
    "UAE": "mea.ast.checkmarx.net",
}


@register
class CheckmarxConnector(Connector):
    spec = ConnectorSpec(
        kind="checkmarx",
        label="Checkmarx One",
        vendor="Checkmarx One",
        description="Applications whose latest Checkmarx One SCA scan includes a vulnerable package for the CVE.",
        host_patterns=tuple(REGIONS.values()),
        auth_hosts=("*.iam.checkmarx.net", "iam.checkmarx.net"),
        base_url_example="https://ast.checkmarx.net",
        regions=tuple((k, f"https://{v}") for k, v in REGIONS.items()),
        fields=(
            ConfigField("tenant", "Tenant name", required=True),
            ConfigField(
                "api_key", "API key", kind="secret", required=True, help="Identity and Access Management → API Keys"
            ),
            ConfigField("max_projects", "Max projects to check", kind="number", default=500),
        ),
        default_field_map={
            "hostname": "project.name",
            "resource_id": "project.id",
            "os": "data.packageIdentifier",
            "owner": "project.tags.owner",
            "business_unit": "project.groups",
            "environment": "project.tags.environment",
            "detection_date": "firstFoundAt",
            "source_ref": "similarityId",
        },
        prerequisites=(
            "Checkmarx One API key for a user with view-projects and view-results permissions",
            "Tenant name and region; SCA scanner enabled on the projects",
        ),
        docs="integrations/checkmarx/",
        rate=(10, 1.0),
        category="Application security (SCA / code)",
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _iam(self) -> str:
        host = (urlsplit(self.base_url).hostname or "").lower()
        return "https://" + host.replace("ast.checkmarx.net", "iam.checkmarx.net")

    def _token(self) -> tuple[str, int]:
        tenant = str(self.config.get("tenant") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", tenant):
            raise ConnectorError("Tenant name contains invalid characters")
        resp = self.client.request(
            "POST",
            f"{self._iam()}/auth/realms/{tenant}/protocol/openid-connect/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "ast-app",
                "refresh_token": self.secrets.get("api_key", ""),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body = json_body(resp, "Checkmarx IAM")
        if not body.get("access_token"):
            raise ConnectorError("Checkmarx did not return an access token — check tenant, region and API key")
        return body["access_token"], int(body.get("expires_in", 1800))

    def _get(self, path: str, params: dict[str, Any] | list[tuple[str, Any]]) -> Any:
        token = self._tokens.get(self._token)
        resp = self.client.request(
            "GET",
            self.url(path),
            params=params,  # type: ignore[arg-type]
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json; version=1.0"},
        )
        return json_body(resp, "Checkmarx One")

    def test_connection(self) -> str:
        body = self._get("/api/projects", {"limit": 1})
        return f"Connected to Checkmarx One ({body.get('totalCount', 0)} projects)"

    def _projects(self) -> Iterator[dict[str, Any]]:
        cap, offset = int(self.config.get("max_projects") or 500), 0
        while offset < cap:
            rows = (
                self._get("/api/projects", {"limit": min(PAGE, cap - offset), "offset": offset}).get("projects") or []
            )
            yield from rows
            offset += len(rows)
            if len(rows) < PAGE:
                return

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        projects = {p["id"]: p for p in self._projects() if p.get("id")}
        ids = list(projects)
        for i in range(0, len(ids), 50):
            chunk = ids[i : i + 50]
            last = self._get(
                "/api/projects/last-scan",
                [("project-ids", pid) for pid in chunk] + [("scan-status", "Completed"), ("limit", 50)],
            )
            scans = last if isinstance(last, dict) else {}
            for pid in chunk:
                scan = scans.get(pid) or {}
                if not scan.get("id"):
                    continue
                offset = 0
                while True:
                    res = self._get("/api/results", {"scan-id": scan["id"], "limit": RESULTS_PAGE, "offset": offset})
                    rows = res.get("results") or []
                    for r in rows:
                        cve = (r.get("vulnerabilityDetails") or {}).get("cveName") or r.get("id")
                        if (
                            r.get("type") == "sca"
                            and str(cve).upper() == cve_id
                            and r.get("state") != "NOT_EXPLOITABLE"
                        ):
                            yield {**r, "project": projects[pid], "scan": {"id": scan["id"]}}
                    offset += len(rows)
                    if len(rows) < RESULTS_PAGE or offset >= int(res.get("totalCount") or 0):
                        break

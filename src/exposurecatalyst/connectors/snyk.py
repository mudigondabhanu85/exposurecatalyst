"""Snyk — projects (repos, container images, IaC) with an open issue for the CVE.

Uses the v1 Reporting API ``POST /v1/reporting/issues/latest`` with ``filters.identifier = <CVE>`` (the REST
issues API has no CVE filter). Auth: ``Authorization: token <service-account token>``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    json_body,
    register,
)

PAGE = 1000
MAX_PAGES = 100
UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


@register
class SnykConnector(Connector):
    spec = ConnectorSpec(
        kind="snyk",
        label="Snyk",
        vendor="Snyk",
        description="Projects (code repos, container images, IaC) with an open Snyk issue for the CVE.",
        host_patterns=("api.snyk.io", "api.us.snyk.io", "api.eu.snyk.io", "api.au.snyk.io"),
        base_url_example="https://api.snyk.io",
        regions=(
            ("SNYK-US-01", "https://api.snyk.io"),
            ("SNYK-US-02", "https://api.us.snyk.io"),
            ("SNYK-EU-01", "https://api.eu.snyk.io"),
            ("SNYK-AU-01", "https://api.au.snyk.io"),
        ),
        fields=(
            ConfigField("api_token", "Service account token", kind="secret", required=True),
            ConfigField("org_ids", "Organization IDs", required=True, help="Comma-separated org UUIDs"),
        ),
        default_field_map={
            "hostname": "project.name",
            "resource_id": "project.id",
            "os": "project.targetFile",
            "owner": "project.owner",
            "environment": "project.environment",
            "detection_date": "introducedDate",
            "source_ref": "issue.id",
        },
        prerequisites=(
            "Snyk Enterprise plan (Reporting API) and a service account with the Org Collaborator / read role",
            "Organization IDs (Settings → General → Organization ID)",
        ),
        docs="integrations/snyk/",
        rate=(5, 1.0),
        category="Application security (SCA / code)",
    )

    def _orgs(self) -> list[str]:
        orgs = [o.strip() for o in str(self.config.get("org_ids") or "").split(",") if o.strip()]
        bad = [o for o in orgs if not UUID.match(o)]
        if not orgs or bad:
            raise ConnectorError("Organization IDs must be Snyk org UUIDs")
        return orgs

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"token {self.secrets.get('api_token', '')}"}

    def test_connection(self) -> str:
        org = self._orgs()[0]
        resp = self.client.request(
            "GET", self.url(f"/rest/orgs/{org}"), params={"version": "2024-10-15"}, headers=self._headers()
        )
        name = ((json_body(resp, "Snyk").get("data") or {}).get("attributes") or {}).get("name", org)
        return f"Connected to Snyk organization {name}"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        body = {"filters": {"orgs": self._orgs(), "identifier": cve_id, "isFixed": False, "ignored": False}}
        for page in range(1, MAX_PAGES + 1):
            resp = self.client.request(
                "POST",
                self.url("/v1/reporting/issues/latest"),
                params={"page": page, "perPage": PAGE, "sortBy": "introducedDate"},
                json=body,
                headers=self._headers(),
            )
            data = json_body(resp, "Snyk")
            rows = data.get("results") or []
            yield from rows
            if len(rows) < PAGE or page * PAGE >= int(data.get("total") or 0):
                return
        raise ConnectorError("Snyk pagination did not terminate")

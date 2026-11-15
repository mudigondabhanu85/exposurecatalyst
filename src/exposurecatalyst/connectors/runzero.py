"""runZero — vulnerability records for the CVE via the Export API.

``GET /api/v1.0/export/org/vulnerabilities.json?search=cve:"<CVE>"`` returns every matching vulnerability
record (one per asset) with the asset's names, addresses and OS. Auth: organization *export* token (Bearer).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import ConfigField, Connector, ConnectorError, ConnectorSpec, json_body, register

FIELDS = (
    "vulnerability_id,vulnerability_cve,asset_id,names,addresses,os,os_version,site_name,tags,"
    "vulnerability_first_detected_ts,vulnerability_last_detected_ts,type"
)


@register
class RunZeroConnector(Connector):
    spec = ConnectorSpec(
        kind="runzero",
        label="runZero",
        vendor="runZero",
        description="Assets runZero has seen with the CVE (its own scanning plus imported vulnerability data).",
        host_patterns=("console.runzero.com", "*.runzero.com"),
        base_url_example="https://console.runzero.com",
        fields=(
            ConfigField(
                "api_token",
                "Organization export token",
                kind="secret",
                required=True,
                help="Organization → Export token (read-only)",
            ),
        ),
        default_field_map={
            "hostname": "names.0",
            "ip_address": "addresses.0",
            "os": "os",
            "resource_id": "asset_id",
            "business_unit": "site_name",
            "environment": "tags",
            "detection_date": "vulnerability_first_detected_ts",
            "source_ref": "vulnerability_id",
        },
        prerequisites=(
            "runZero Platform with vulnerability data (scanner or integrations)",
            "Organization export token (read-only); self-hosted consoles must be in EXCAT_EGRESS_ALLOWLIST",
        ),
        docs="integrations/runzero/",
        api_status="confirm",
        rate=(2, 1.0),
        category="Asset inventory (CAASM)",
    )

    def _get(self, path: str, params: dict[str, Any]) -> Any:
        resp = self.client.request(
            "GET",
            self.url(path),
            params=params,
            headers={"Authorization": f"Bearer {self.secrets.get('api_token', '')}"},
        )
        return json_body(resp, "runZero")

    def test_connection(self) -> str:
        self._get("/api/v1.0/export/org/sites.json", {"fields": "id"})
        return "Connected to runZero with the export token"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        rows = self._get(
            "/api/v1.0/export/org/vulnerabilities.json",
            {"search": f'cve:"{cve_id.replace(chr(34), "")}"', "fields": FIELDS},
        )
        if not isinstance(rows, list):
            raise ConnectorError("runZero returned an unexpected export format")
        for r in rows:
            if isinstance(r, dict) and str(r.get("vulnerability_cve") or cve_id).upper() == cve_id:
                yield r

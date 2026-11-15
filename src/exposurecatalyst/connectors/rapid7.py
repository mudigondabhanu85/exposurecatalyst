"""Rapid7 InsightVM — cloud Integrations API v4 (``POST /vm/v4/integration/assets``).

The asset search takes two filter strings in the body: ``asset`` and ``vulnerability``. The default
vulnerability filter is ``vulnerability.cveIds IN ['<CVE>']``; it is a setting because the search language
has evolved between releases. Cursor pagination via ``metadata.cursor``. Auth: ``X-Api-Key`` (Insight
platform user or organization key).
"""

from __future__ import annotations

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

PAGE = 500
MAX_PAGES = 400
REGIONS = ("us", "us2", "us3", "eu", "ca", "au", "ap", "me-central-1", "ap-south-2")


def _quote(cve: str) -> str:
    return cve.replace("'", "").replace("\\", "")


@register
class Rapid7Connector(Connector):
    spec = ConnectorSpec(
        kind="rapid7",
        label="Rapid7 InsightVM",
        vendor="Rapid7 InsightVM",
        description="Assets with the CVE from InsightVM scans and Insight Agents (cloud Integrations API v4).",
        host_patterns=("*.api.insight.rapid7.com",),
        base_url_example="https://us.api.insight.rapid7.com",
        regions=tuple((r.upper(), f"https://{r}.api.insight.rapid7.com") for r in REGIONS),
        fields=(
            ConfigField(
                "api_key",
                "Insight API key",
                kind="secret",
                required=True,
                help="Insight Platform → Settings → API Keys (organization or user key)",
            ),
            ConfigField(
                "vuln_filter",
                "Vulnerability filter",
                default="vulnerability.cveIds IN ['{cve}']",
                help="{cve} is replaced with the CVE ID",
            ),
            ConfigField(
                "asset_filter", "Asset filter (optional)", default="", help="e.g. asset.tags IN ['Production']"
            ),
        ),
        default_field_map={
            "hostname": "host_name",
            "ip_address": "ip",
            "os": "os_description",
            "resource_id": "id",
            "cloud_account": "aws_account_id",
            "detection_date": "last_assessed_for_vulnerabilities",
            "source_ref": "id",
        },
        prerequisites=(
            "InsightVM with the cloud Integrations API (console paired to the Insight Platform)",
            "Insight API key for a user with read access to the relevant sites/asset groups",
            "Your Insight region (the base URL)",
        ),
        docs="integrations/rapid7/",
        api_status="confirm",
        rate=(5, 1.0),
    )

    def _post(self, params: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        resp = self.client.request(
            "POST",
            self.url("/vm/v4/integration/assets"),
            params=params,
            json=body,
            headers={"X-Api-Key": self.secrets.get("api_key", "")},
        )
        data = json_body(resp, "Rapid7")
        if not isinstance(data, dict):
            raise ConnectorError("Rapid7 returned an unexpected response")
        return data

    def test_connection(self) -> str:
        self._post({"size": 1}, {})
        return "Connected to the InsightVM Integrations API"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        body: dict[str, Any] = {
            "vulnerability": (self.config.get("vuln_filter") or "vulnerability.cveIds IN ['{cve}']").replace(
                "{cve}", _quote(cve_id)
            ),
        }
        if self.config.get("asset_filter"):
            body["asset"] = self.config["asset_filter"]
        params: dict[str, Any] = {"size": PAGE}
        for _ in range(MAX_PAGES):
            data = self._post(params, body)
            rows = data.get("data") or []
            yield from rows
            cursor = (data.get("metadata") or {}).get("cursor")
            if not rows or not cursor or cursor == params.get("cursor"):
                return
            params["cursor"] = cursor
        raise ConnectorError("Rapid7 pagination did not terminate")

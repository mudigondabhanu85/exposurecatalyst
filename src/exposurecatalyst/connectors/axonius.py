"""Axonius — devices whose aggregated software CVEs include the CVE (REST API v1, ``POST /api/devices``).

The AQL filter ``("specific_data.data.software_cves.cve_id" == "<CVE>")`` runs over the correlated device
view; fields are requested explicitly and offset-paged. Auth: ``api-key`` + ``api-secret`` headers.
Axonius returns dotted field names as keys, so records are nested before field mapping.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    first,
    flatten_keys,
    json_body,
    register,
)

PAGE = 500
MAX_PAGES = 400
FIELDS = [
    "internal_axon_id",
    "specific_data.data.hostname",
    "specific_data.data.network_interfaces.ips",
    "specific_data.data.os.type_distribution",
    "specific_data.data.cloud_id",
    "specific_data.data.cloud_account",
    "specific_data.data.owner",
    "specific_data.data.first_seen",
    "labels",
]


@register
class AxoniusConnector(Connector):
    spec = ConnectorSpec(
        kind="axonius",
        label="Axonius",
        vendor="Axonius",
        description="Correlated devices (from every Axonius adapter) whose software has the CVE.",
        host_patterns=("*.axonius.com", "*.on.axonius.com"),
        base_url_example="https://example.on.axonius.com",
        fields=(
            ConfigField("api_key", "API key", kind="secret", required=True),
            ConfigField("api_secret", "API secret", kind="secret", required=True),
            ConfigField(
                "extra_aql",
                "Extra AQL (optional)",
                default="",
                help='ANDed with the CVE filter, e.g. ("labels" == "Production")',
            ),
        ),
        default_field_map={
            "hostname": "specific_data.data.hostname",
            "ip_address": "specific_data.data.network_interfaces.ips",
            "os": "specific_data.data.os.type_distribution",
            "cloud_account": "specific_data.data.cloud_account",
            "resource_id": "specific_data.data.cloud_id",
            "owner": "specific_data.data.owner",
            "environment": "labels",
            "detection_date": "specific_data.data.first_seen",
            "source_ref": "internal_axon_id",
        },
        prerequisites=(
            "API key and secret for a user with the Viewer role (Account → API Key)",
            "Software/vulnerability adapters connected so devices carry software CVEs",
            "Add the host to EXCAT_EGRESS_ALLOWLIST for an on-prem instance",
        ),
        docs="integrations/axonius/",
        rate=(5, 1.0),
        category="Asset inventory (CAASM)",
    )

    def _headers(self) -> dict[str, str]:
        return {
            "api-key": self.secrets.get("api_key", ""),
            "api-secret": self.secrets.get("api_secret", ""),
            "Content-Type": "application/vnd.api+json",
        }

    def test_connection(self) -> str:
        resp = self.client.request("GET", self.url("/api/settings/meta/about"), headers=self._headers())
        about = json_body(resp, "Axonius")
        version = (
            ((about.get("data") or {}).get("attributes") or {}).get("Version") if isinstance(about, dict) else None
        )
        return "Connected to Axonius" + (f" {version}" if version else "")

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        aql = f'("specific_data.data.software_cves.cve_id" == "{cve_id.replace(chr(34), "")}")'
        if self.config.get("extra_aql"):
            aql = f"{aql} and ({self.config['extra_aql']})"
        offset = 0
        for _ in range(MAX_PAGES):
            body = {
                "data": {
                    "type": "entity_request_schema",
                    "attributes": {
                        "filter": aql,
                        "fields": {"devices": FIELDS},
                        "page": {"limit": PAGE, "offset": offset},
                        "use_cache_entry": False,
                        "include_details": False,
                    },
                }
            }
            resp = self.client.request("POST", self.url("/api/devices"), json=body, headers=self._headers())
            rows = json_body(resp, "Axonius").get("data") or []
            for r in rows:
                attrs = dict(r.get("attributes") or {})
                for k in (
                    "specific_data.data.hostname",
                    "specific_data.data.cloud_id",
                    "specific_data.data.cloud_account",
                    "specific_data.data.owner",
                    "specific_data.data.os.type_distribution",
                    "specific_data.data.first_seen",
                ):
                    attrs[k] = first(attrs.get(k))
                attrs.setdefault("internal_axon_id", r.get("id"))
                yield flatten_keys(attrs)
            offset += len(rows)
            if len(rows) < PAGE:
                return
        raise ConnectorError("Axonius pagination did not terminate")

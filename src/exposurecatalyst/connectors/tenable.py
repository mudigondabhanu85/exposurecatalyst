"""Tenable Vulnerability Management (Tenable.io) and Tenable Security Center (Tenable.sc).

* Tenable.io: ``GET /workbenches/assets`` filtered by ``plugin.attributes.cve.raw`` = CVE (one call returns up
  to 5,000 assets seen in the last *N* days). Auth: ``X-ApiKeys: accessKey=…;secretKey=…``.
* Tenable.sc: ``POST /rest/analysis`` (``type=vuln``, tool ``listvuln``, filter ``cveID = CVE``), paged with
  ``startOffset``/``endOffset``. Auth: ``x-apikey: accesskey=…; secretkey=…;`` (API keys, 5.13+).
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
    json_body,
    register,
)

SC_PAGE = 1000
SC_MAX_PAGES = 200


def _keys(secrets: dict[str, str]) -> tuple[str, str]:
    return secrets.get("access_key", ""), secrets.get("secret_key", "")


@register
class TenableIoConnector(Connector):
    spec = ConnectorSpec(
        kind="tenable_io",
        label="Tenable Vulnerability Management",
        vendor="Tenable Vulnerability Management (Tenable.io)",
        description="Assets with the CVE from Tenable Vulnerability Management scans and agents.",
        host_patterns=("cloud.tenable.com", "fedcloud.tenable.com"),
        base_url_example="https://cloud.tenable.com",
        regions=(("Commercial", "https://cloud.tenable.com"), ("FedRAMP", "https://fedcloud.tenable.com")),
        fields=(
            ConfigField("access_key", "Access key", kind="secret", required=True),
            ConfigField("secret_key", "Secret key", kind="secret", required=True),
            ConfigField(
                "date_range",
                "Look-back (days)",
                kind="number",
                default=30,
                help="Assets with the vulnerability seen in the last N days",
            ),
        ),
        default_field_map={
            "hostname": "fqdn.0",
            "ip_address": "ipv4.0",
            "os": "operating_system.0",
            "cloud_account": "aws_owner_id",
            "resource_id": "aws_ec2_instance_id.0",
            "detection_date": "last_seen",
            "source_ref": "id",
        },
        prerequisites=(
            "API keys for a user with the Basic or Scan Operator role and CAN VIEW on the relevant asset tags",
            "Settings → My Account → API Keys (keys are shown once)",
        ),
        docs="integrations/tenable/",
        rate=(5, 1.0),
    )

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        ak, sk = _keys(self.secrets)
        resp = self.client.request(
            "GET", self.url(path), params=params, headers={"X-ApiKeys": f"accessKey={ak};secretKey={sk}"}
        )
        return json_body(resp, "Tenable")

    def test_connection(self) -> str:
        me = self._get("/session")
        return f"Connected to Tenable Vulnerability Management as {me.get('username', 'API user')}"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        body = self._get(
            "/workbenches/assets",
            {
                "date_range": int(self.config.get("date_range") or 30),
                "filter.0.filter": "plugin.attributes.cve.raw",
                "filter.0.quality": "eq",
                "filter.0.value": cve_id,
                "filter.search_type": "and",
            },
        )
        for a in body.get("assets") or []:
            if not a.get("fqdn") and a.get("netbios_name"):
                a["fqdn"] = a["netbios_name"]
            if not a.get("fqdn") and a.get("hostname"):
                a["fqdn"] = a["hostname"]
            yield a


@register
class TenableScConnector(Connector):
    spec = ConnectorSpec(
        kind="tenable_sc",
        label="Tenable Security Center",
        vendor="Tenable Security Center (Tenable.sc)",
        description="Vulnerability instances for the CVE across Tenable Security Center repositories (on-prem).",
        host_patterns=(),
        base_url_example="https://securitycenter.example.internal",
        fields=(
            ConfigField("access_key", "Access key", kind="secret", required=True),
            ConfigField("secret_key", "Secret key", kind="secret", required=True),
            ConfigField(
                "source_type", "Data source", kind="select", default="cumulative", options=("cumulative", "patched")
            ),
        ),
        default_field_map={
            "hostname": "dnsName",
            "ip_address": "ip",
            "os": "operatingSystem",
            "resource_id": "uuid",
            "business_unit": "repository.name",
            "detection_date": "firstSeen",
            "source_ref": "pluginID",
        },
        prerequisites=(
            "Tenable Security Center 5.13+ with API keys enabled (System → Configuration → Security)",
            "Keys for a user whose group can view the relevant repositories",
            "Add the console host to EXCAT_EGRESS_ALLOWLIST (self-hosted)",
        ),
        docs="integrations/tenable-sc/",
        rate=(10, 1.0),
    )

    def _headers(self) -> dict[str, str]:
        ak, sk = _keys(self.secrets)
        return {"x-apikey": f"accesskey={ak}; secretkey={sk};"}

    def _check(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict) or body.get("error_code"):
            raise ConnectorError(f"Tenable.sc error: {(body or {}).get('error_msg', 'unexpected response')[:200]}")
        return body.get("response") or {}

    def test_connection(self) -> str:
        resp = self.client.request("GET", self.url("/rest/currentUser"), headers=self._headers())
        user = self._check(json_body(resp, "Tenable.sc"))
        return f"Connected to Tenable Security Center as {user.get('username', 'API user')}"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        start = 0
        for _ in range(SC_MAX_PAGES):
            payload = {
                "type": "vuln",
                "sourceType": self.config.get("source_type") or "cumulative",
                "query": {
                    "type": "vuln",
                    "tool": "listvuln",
                    "startOffset": start,
                    "endOffset": start + SC_PAGE,
                    "filters": [{"filterName": "cveID", "operator": "=", "value": cve_id}],
                },
            }
            resp = self.client.request("POST", self.url("/rest/analysis"), json=payload, headers=self._headers())
            r = self._check(json_body(resp, "Tenable.sc"))
            rows = r.get("results") or []
            for row in rows:
                row["dnsName"] = row.get("dnsName") or row.get("netbiosName") or None
                if isinstance(row.get("operatingSystem"), str):
                    row["operatingSystem"] = row["operatingSystem"].replace("<br/>", " / ")
                yield row
            start += len(rows)
            total = int(first(r.get("totalRecords")) or 0)
            if not rows or start >= total:
                return
        raise ConnectorError("Tenable.sc pagination did not terminate")

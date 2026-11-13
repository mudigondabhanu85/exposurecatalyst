"""ServiceNow — CMDB via the Table API.

* Affected assets for a CVE: Vulnerability Response's ``sn_vul_vulnerable_item`` (query
  ``vulnerability.id=<CVE>``), dot-walking to the configuration item. Without Vulnerability Response,
  leave "Vulnerable item table" empty: the connector then reports CVE lookups as *unsupported* and is used
  for enrichment only.
* Enrichment: ``fetch_asset_details`` looks a host up in ``cmdb_ci_computer`` by name or IP so assets from
  other tools gain owner / business unit / environment.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    UnsupportedError,
    register,
)

PAGE = 1000
CI_FIELDS = "sys_id,name,ip_address,os,owned_by,department,used_for,company,serial_number,object_id"


def _q(value: str) -> str:
    """Encoded-query injection guard: '^' separates clauses, so strip it (and newlines) from values."""
    return value.replace("^", "").replace("\n", "").replace("\r", "")


@register
class ServiceNowCmdbConnector(Connector):
    spec = ConnectorSpec(
        kind="servicenow_cmdb",
        label="ServiceNow CMDB",
        vendor="ServiceNow",
        description="CMDB configuration items affected by a CVE (via Vulnerability Response) and owner / "
        "business unit / environment enrichment for assets from every other source.",
        host_patterns=("*.service-now.com", "*.servicenowservices.com"),
        base_url_example="https://example.service-now.com",
        fields=(
            ConfigField("username", "Integration user", required=True),
            ConfigField("password", "Password", kind="secret", required=True),
            ConfigField(
                "vuln_table",
                "Vulnerable item table",
                default="sn_vul_vulnerable_item",
                help="Leave empty if Vulnerability Response is not licensed (enrichment only)",
            ),
            ConfigField("ci_table", "CI table for enrichment", default="cmdb_ci_computer"),
            ConfigField("enrich", "Enrich assets from other sources", kind="bool", default=True),
        ),
        default_field_map={
            "hostname": "cmdb_ci.name",
            "ip_address": "cmdb_ci.ip_address",
            "os": "cmdb_ci.os",
            "resource_id": "cmdb_ci.object_id",
            "owner": "cmdb_ci.owned_by",
            "business_unit": "cmdb_ci.department",
            "environment": "cmdb_ci.used_for",
            "detection_date": "first_found",
            "source_ref": "number",
        },
        prerequisites=(
            "Integration user with roles: cmdb_read (+ sn_vul.read_only for Vulnerability Response)",
            "Web service access only (no interactive login) on the user record",
            "Table API access to cmdb_ci_computer and sn_vul_vulnerable_item (ACLs)",
        ),
        docs="integrations/servicenow-cmdb/",
        rate=(20, 1.0),
        capabilities=("assets_for_cve", "asset_details"),
    )

    def _table(self, table: str, params: dict[str, Any]) -> tuple[list[dict[str, Any]], int | None]:
        if not table.replace("_", "").isalnum():
            raise ConnectorError("invalid table name")
        resp = self.client.request(
            "GET",
            self.url(f"/api/now/table/{table}"),
            params={"sysparm_display_value": "true", "sysparm_exclude_reference_link": "true", **params},
            auth=(self.config["username"], self.secrets.get("password", "")),
        )
        total = resp.headers.get("X-Total-Count")
        return resp.json().get("result", []), int(total) if total and total.isdigit() else None

    def test_connection(self) -> str:
        self._table(
            self.config.get("ci_table") or "cmdb_ci_computer", {"sysparm_limit": "1", "sysparm_fields": "sys_id"}
        )
        return "Connected to ServiceNow and read the CMDB"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        table = (self.config.get("vuln_table") or "").strip()
        if not table:
            raise UnsupportedError("Vulnerability Response table not configured — CMDB used for enrichment only")
        fields = ",".join(["number", "first_found", "state", *[f"cmdb_ci.{f}" for f in CI_FIELDS.split(",")]])
        offset = 0
        while True:
            rows, total = self._table(
                table,
                {
                    "sysparm_query": f"vulnerability.id={_q(cve_id)}^active=true",
                    "sysparm_fields": fields,
                    "sysparm_limit": str(PAGE),
                    "sysparm_offset": str(offset),
                },
            )
            for r in rows:  # flat dot-walked keys → nested, so field-map paths read naturally
                nested: dict[str, Any] = {}
                for k, v in r.items():
                    cur = nested
                    *parents, leaf = k.split(".")
                    for p in parents:
                        cur = cur.setdefault(p, {})
                    cur[leaf] = v
                yield nested
            offset += len(rows)
            if len(rows) < PAGE or (total is not None and offset >= total):
                return

    def fetch_asset_details(self, *, hostname: str | None = None, ip: str | None = None) -> dict[str, Any] | None:
        clauses = []
        if hostname:
            clauses.append(f"name={_q(hostname.split('.')[0])}")
            clauses.append(f"name={_q(hostname)}")
        if ip:
            clauses.append(f"ip_address={_q(ip)}")
        if not clauses:
            return None
        rows, _ = self._table(
            self.config.get("ci_table") or "cmdb_ci_computer",
            {"sysparm_query": "^OR".join(clauses), "sysparm_fields": CI_FIELDS, "sysparm_limit": "1"},
        )
        return {"cmdb_ci": rows[0]} if rows else None

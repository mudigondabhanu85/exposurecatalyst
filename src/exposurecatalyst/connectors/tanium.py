"""Tanium — Gateway GraphQL API (``/plugin/products/gateway/graphql``) with an API token.

Endpoints are selected with a sensor filter: the sensor (default "Comply - Vulnerability Details") must
report CVE IDs; the filter matches endpoints whose sensor value CONTAINS the CVE ID. Sensor name and
operator are configurable because Tanium deployments differ (Comply vs. custom sensors).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import ConfigField, Connector, ConnectorError, ConnectorSpec, register

GATEWAY = "/plugin/products/gateway/graphql"
QUERY = """
query ExcatEndpoints($first: Int, $after: Cursor, $filter: EndpointFieldFilter) {
  endpoints(first: $first, after: $after, filter: $filter) {
    edges { node { id eid name ipAddress os { name platform } lastLoggedInUser } }
    pageInfo { hasNextPage endCursor }
  }
}"""


@register
class TaniumConnector(Connector):
    spec = ConnectorSpec(
        kind="tanium",
        label="Tanium",
        vendor="Tanium",
        description="Endpoints whose Tanium Comply (or custom) sensor reports the CVE.",
        host_patterns=("*.cloud.tanium.com", "*.titankube.com"),
        base_url_example="https://example-api.cloud.tanium.com",
        fields=(
            ConfigField(
                "api_token",
                "API token",
                kind="secret",
                required=True,
                help="Tanium Console → Administration → API Tokens",
            ),
            ConfigField(
                "cve_sensor",
                "CVE sensor name",
                default="Comply - Vulnerability Details",
                help="Sensor whose values contain CVE IDs",
            ),
            ConfigField("operator", "Match operator", kind="select", default="CONTAINS", options=("CONTAINS", "EQ")),
        ),
        default_field_map={
            "hostname": "name",
            "ip_address": "ipAddress",
            "os": "os.name",
            "resource_id": "eid",
            "owner": "lastLoggedInUser",
            "source_ref": "id",
        },
        prerequisites=(
            "Tanium API Gateway enabled (Tanium Cloud or on-prem 7.5+)",
            "API token for a user with read-only Gateway + Comply permissions",
            "Tanium Comply vulnerability scanning deployed (or a custom sensor returning CVE IDs)",
        ),
        docs="integrations/tanium/",
        rate=(10, 1.0),
    )

    def _gql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        resp = self.client.request(
            "POST",
            self.url(GATEWAY),
            json={"query": query, "variables": variables},
            headers={"session": self.secrets.get("api_token", "")},
        )
        body = resp.json()
        if body.get("errors"):
            raise ConnectorError(
                "Tanium Gateway error: " + "; ".join(e.get("message", "?") for e in body["errors"])[:300]
            )
        return body["data"]

    def test_connection(self) -> str:
        self._gql("query { endpoints(first: 1) { edges { node { id } } } }", {})
        return "Connected to the Tanium API Gateway"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        flt = {
            "sensor": {"name": self.config.get("cve_sensor")},
            "op": self.config.get("operator") or "CONTAINS",
            "value": cve_id,
        }
        after = None
        while True:
            page = self._gql(QUERY, {"first": 500, "after": after, "filter": flt})["endpoints"]
            for edge in page["edges"]:
                yield edge["node"]
            if not page["pageInfo"]["hasNextPage"]:
                return
            after = page["pageInfo"]["endCursor"]

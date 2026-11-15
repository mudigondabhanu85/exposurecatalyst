"""Wiz — OAuth2 client credentials + GraphQL ``vulnerabilityFindings`` filtered by exact CVE."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import ConfigField, Connector, ConnectorError, ConnectorSpec, TokenCache, register

QUERY = """
query ExcatVulnFindings($filterBy: VulnerabilityFindingFilters, $first: Int, $after: String) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id name status firstDetectedAt
      vulnerableAsset {
        ... on VulnerableAssetBase { id name type providerUniqueId cloudPlatform subscriptionExternalId }
        ... on VulnerableAssetVirtualMachine { operatingSystem ipAddresses }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}"""


@register
class WizConnector(Connector):
    spec = ConnectorSpec(
        kind="wiz",
        label="Wiz",
        vendor="Wiz",
        description="Cloud workloads (VMs, containers, serverless) with open Wiz vulnerability findings.",
        host_patterns=("*.app.wiz.io", "*.app.wiz.us"),
        base_url_example="https://api.us17.app.wiz.io/graphql",
        fields=(
            ConfigField("client_id", "Service account client ID", required=True),
            ConfigField("client_secret", "Service account client secret", kind="secret", required=True),
            ConfigField(
                "auth_url",
                "Token URL",
                kind="url",
                default="https://auth.app.wiz.io/oauth/token",
                help="auth.app.wiz.io (commercial) or auth.app.wiz.us (FedRAMP)",
            ),
            ConfigField("statuses", "Finding statuses", default="OPEN", help="Comma-separated, e.g. OPEN,IN_PROGRESS"),
        ),
        default_field_map={
            "hostname": "vulnerableAsset.name",
            "ip_address": "vulnerableAsset.ipAddresses.0",
            "os": "vulnerableAsset.operatingSystem",
            "cloud_account": "vulnerableAsset.subscriptionExternalId",
            "resource_id": "vulnerableAsset.providerUniqueId",
            "detection_date": "firstDetectedAt",
            "source_ref": "id",
        },
        prerequisites=(
            "Wiz service account (Settings → Service Accounts) of type 'Custom Integration (GraphQL API)'",
            "Scope: read:vulnerabilities (and read:resources for asset details)",
            "Your tenant's API endpoint URL (User Settings → Tenant info)",
        ),
        docs="integrations/wiz/",
        rate=(3, 1.0),
        category="Cloud security (CNAPP)",
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _token(self) -> tuple[str, int]:
        from exposurecatalyst.security.ssrf import host_matches

        auth_url = self.config.get("auth_url") or "https://auth.app.wiz.io/oauth/token"
        from urllib.parse import urlsplit

        if not host_matches((urlsplit(auth_url).hostname or "").lower(), ("auth.app.wiz.io", "auth.app.wiz.us")):
            raise ConnectorError("Token URL must be auth.app.wiz.io or auth.app.wiz.us")
        resp = self.client.request(
            "POST",
            auth_url,
            data={
                "grant_type": "client_credentials",
                "audience": "wiz-api",
                "client_id": self.config["client_id"],
                "client_secret": self.secrets.get("client_secret", ""),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body = resp.json()
        if "access_token" not in body:
            raise ConnectorError("Wiz did not return an access token — check the client ID/secret")
        return body["access_token"], int(body.get("expires_in", 3600))

    def _gql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        token = self._tokens.get(self._token)
        resp = self.client.request(
            "POST",
            self.base_url,
            json={"query": query, "variables": variables},
            headers={"Authorization": f"Bearer {token}"},
        )
        body = resp.json()
        if body.get("errors"):
            raise ConnectorError("Wiz GraphQL error: " + "; ".join(e.get("message", "?") for e in body["errors"])[:300])
        return body["data"]

    def test_connection(self) -> str:
        self._gql("query { vulnerabilityFindings(first: 1) { nodes { id } } }", {})
        return "Authenticated to Wiz and read vulnerability findings"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        statuses = [s.strip() for s in (self.config.get("statuses") or "OPEN").split(",") if s.strip()]
        after = None
        while True:
            data = self._gql(
                QUERY,
                {"first": 500, "after": after, "filterBy": {"vulnerabilityExternalId": [cve_id], "status": statuses}},
            )
            page = data["vulnerabilityFindings"]
            yield from page["nodes"]
            if not page["pageInfo"]["hasNextPage"]:
                return
            after = page["pageInfo"]["endCursor"]

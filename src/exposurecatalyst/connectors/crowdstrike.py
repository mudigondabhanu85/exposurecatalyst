"""CrowdStrike Falcon Exposure Management (Spotlight).

OAuth2 client credentials (``POST /oauth2/token``), then
``GET /spotlight/combined/vulnerabilities/v1?filter=cve.id:'<CVE>'+status:['open','reopen']&facet=host_info``
with ``after``-token pagination. Required API scope: *Vulnerabilities: Read*.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    TokenCache,
    json_body,
    register,
)

PAGE = 400
MAX_PAGES = 500


def _fql(value: str) -> str:
    """FQL injection guard: values are single-quoted; strip quotes, '+' (AND) and ',' (OR)."""
    return "".join(c for c in value if c not in "'+,[]\\")


@register
class CrowdStrikeConnector(Connector):
    spec = ConnectorSpec(
        kind="crowdstrike",
        label="CrowdStrike Falcon Spotlight",
        vendor="CrowdStrike Falcon Spotlight",
        description="Hosts with an open Falcon Spotlight vulnerability for the CVE (sensor-based, no scans).",
        host_patterns=(
            "api.crowdstrike.com",
            "api.us-2.crowdstrike.com",
            "api.eu-1.crowdstrike.com",
            "api.laggar.gcw.crowdstrike.com",
        ),
        base_url_example="https://api.crowdstrike.com",
        regions=(
            ("US-1", "https://api.crowdstrike.com"),
            ("US-2", "https://api.us-2.crowdstrike.com"),
            ("EU-1", "https://api.eu-1.crowdstrike.com"),
            ("US-GOV-1", "https://api.laggar.gcw.crowdstrike.com"),
        ),
        fields=(
            ConfigField("client_id", "API client ID", required=True),
            ConfigField("client_secret", "API client secret", kind="secret", required=True),
            ConfigField("statuses", "Statuses", default="open,reopen", help="Comma-separated Spotlight statuses"),
            ConfigField("member_cid", "Member CID (Flight Control, optional)", default=""),
        ),
        default_field_map={
            "hostname": "host_info.hostname",
            "ip_address": "host_info.local_ip",
            "os": "host_info.os_version",
            "cloud_account": "host_info.service_provider_account_id",
            "resource_id": "host_info.instance_id",
            "business_unit": "host_info.groups.name",
            "environment": "host_info.tags",
            "detection_date": "created_timestamp",
            "source_ref": "id",
        },
        prerequisites=(
            "Falcon Spotlight / Exposure Management subscription",
            "API client (Support and resources → API clients and keys) with scope Vulnerabilities: Read",
            "Your cloud's API base URL (US-1, US-2, EU-1 or US-GOV-1)",
        ),
        docs="integrations/crowdstrike/",
        rate=(10, 1.0),
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _token(self) -> tuple[str, int]:
        data = {"client_id": self.config["client_id"], "client_secret": self.secrets.get("client_secret", "")}
        if self.config.get("member_cid"):
            data["member_cid"] = self.config["member_cid"]
        resp = self.client.request(
            "POST",
            self.url("/oauth2/token"),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            ok_statuses=(200, 201),
        )
        body = json_body(resp, "CrowdStrike")
        if not body.get("access_token"):
            raise ConnectorError("CrowdStrike did not return an access token — check the client ID/secret")
        return body["access_token"], int(body.get("expires_in", 1799))

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        token = self._tokens.get(self._token)
        resp = self.client.request("GET", self.url(path), params=params, headers={"Authorization": f"Bearer {token}"})
        body = json_body(resp, "CrowdStrike")
        if body.get("errors"):
            raise ConnectorError("CrowdStrike error: " + "; ".join(str(e.get("message")) for e in body["errors"])[:300])
        return body

    def test_connection(self) -> str:
        self._get("/spotlight/queries/vulnerabilities/v1", {"filter": "status:'open'", "limit": 1})
        return "Authenticated to CrowdStrike and read Spotlight vulnerabilities"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        statuses = [_fql(s.strip()) for s in (self.config.get("statuses") or "open,reopen").split(",") if s.strip()]
        flt = f"cve.id:'{_fql(cve_id)}'" + (
            "+status:[" + ",".join(f"'{s}'" for s in statuses) + "]" if statuses else ""
        )
        params: dict[str, Any] = {"filter": flt, "facet": "host_info", "limit": PAGE}
        for _ in range(MAX_PAGES):
            body = self._get("/spotlight/combined/vulnerabilities/v1", params)
            rows = body.get("resources") or []
            yield from rows
            after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
            if not rows or not after:
                return
            params["after"] = after
        raise ConnectorError("CrowdStrike pagination did not terminate")

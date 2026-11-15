"""Armis Centrix — devices with the CVE via AQL ``in:devices vulnerabilities:(id:"<CVE>")``.

Auth: secret key → ``POST /api/v1/access_token/`` → token sent as ``Authorization: <token>``. Search:
``GET /api/v1/search/`` with ``from``/``length`` paging (``data.next``).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
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

PAGE = 1000
MAX_PAGES = 200
FIELDS = (
    "id,name,ipAddress,macAddress,operatingSystem,operatingSystemVersion,type,category,site,tags,boundaries,"
    "firstSeen,lastSeen,businessImpact"
)


@register
class ArmisConnector(Connector):
    spec = ConnectorSpec(
        kind="armis",
        label="Armis",
        vendor="Armis Centrix",
        description="Managed, unmanaged, IoT and OT devices Armis associates with the CVE.",
        host_patterns=("*.armis.com",),
        base_url_example="https://example.armis.com",
        fields=(
            ConfigField("secret_key", "API secret key", kind="secret", required=True, help="Settings → API Management"),
        ),
        default_field_map={
            "hostname": "name",
            "ip_address": "ipAddress",
            "os": "operatingSystem",
            "resource_id": "macAddress",
            "business_unit": "site.name",
            "environment": "boundaries",
            "detection_date": "firstSeen",
            "source_ref": "id",
        },
        prerequisites=(
            "Armis API secret key for a user with read-only (Read Only / Viewer) permissions",
            "Your tenant URL (https://<tenant>.armis.com)",
        ),
        docs="integrations/armis/",
        api_status="confirm",
        rate=(5, 1.0),
        category="Asset inventory (CAASM)",
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _token(self) -> tuple[str, int]:
        resp = self.client.request(
            "POST", self.url("/api/v1/access_token/"), data={"secret_key": self.secrets.get("secret_key", "")}
        )
        data = json_body(resp, "Armis").get("data") or {}
        token = data.get("access_token")
        if not token:
            raise ConnectorError("Armis did not return an access token — check the secret key")
        ttl = 600
        try:
            exp = datetime.fromisoformat(str(data.get("expiration_utc")).replace("Z", "+00:00"))
            ttl = max(120, int((exp.replace(tzinfo=exp.tzinfo or UTC) - datetime.now(UTC)).total_seconds()))
        except ValueError:
            pass
        return token, ttl

    def _search(self, aql: str, start: int, length: int) -> dict[str, Any]:
        token = self._tokens.get(self._token)
        resp = self.client.request(
            "GET",
            self.url("/api/v1/search/"),
            headers={"Authorization": token},
            params={"aql": aql, "from": start, "length": length, "fields": FIELDS},
        )
        body = json_body(resp, "Armis")
        if body.get("success") is False:
            raise ConnectorError(f"Armis error: {str(body.get('message'))[:200]}")
        return body.get("data") or {}

    def test_connection(self) -> str:
        self._search('in:devices timeFrame:"1 Days"', 0, 1)
        return "Authenticated to Armis and searched devices"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        aql = f'in:devices vulnerabilities:(id:"{cve_id.replace(chr(34), "")}")'
        start = 0
        for _ in range(MAX_PAGES):
            data = self._search(aql, start, PAGE)
            rows = data.get("results") or []
            yield from rows
            nxt = data.get("next")
            if not rows or nxt in (None, "", start):
                return
            start = int(nxt)
        raise ConnectorError("Armis pagination did not terminate")

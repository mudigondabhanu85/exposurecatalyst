"""Microsoft Defender Vulnerability Management (Defender for Endpoint API).

Entra ID app (client credentials, ``https://api.securitycenter.microsoft.com/.default``), then
``GET /api/machines/SoftwareVulnerabilitiesByMachine?$filter=cveId eq '<CVE>'`` with ``@odata.nextLink``
pagination. Required application permission: *Vulnerability.Read.All* (plus *Machine.Read.All* for IPs).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    TokenCache,
    json_body,
    register,
)
from exposurecatalyst.security.ssrf import host_matches

MAX_PAGES = 500
LOGIN = {"Commercial": "https://login.microsoftonline.com", "GCC High / DoD": "https://login.microsoftonline.us"}
SCOPE = {
    "Commercial": "https://api.securitycenter.microsoft.com/.default",
    "GCC High / DoD": "https://api-gov.securitycenter.microsoft.us/.default",
}


@register
class DefenderConnector(Connector):
    spec = ConnectorSpec(
        kind="defender",
        label="Microsoft Defender VM",
        vendor="Microsoft Defender Vulnerability Management",
        description="Devices exposed to the CVE according to Defender Vulnerability Management.",
        host_patterns=(
            "api.securitycenter.microsoft.com",
            "api-us.securitycenter.microsoft.com",
            "api-eu.securitycenter.microsoft.com",
            "api-uk.securitycenter.microsoft.com",
            "api-au.securitycenter.microsoft.com",
            "api.security.microsoft.com",
            "*.securitycenter.microsoft.us",
        ),
        auth_hosts=("login.microsoftonline.com", "login.microsoftonline.us"),
        base_url_example="https://api.securitycenter.microsoft.com",
        regions=(
            ("Global", "https://api.securitycenter.microsoft.com"),
            ("US", "https://api-us.securitycenter.microsoft.com"),
            ("EU", "https://api-eu.securitycenter.microsoft.com"),
            ("UK", "https://api-uk.securitycenter.microsoft.com"),
            ("GCC", "https://api-gcc.securitycenter.microsoft.us"),
            ("GCC High / DoD", "https://api-gov.securitycenter.microsoft.us"),
        ),
        fields=(
            ConfigField("tenant_id", "Directory (tenant) ID", required=True),
            ConfigField("client_id", "Application (client) ID", required=True),
            ConfigField("client_secret", "Client secret", kind="secret", required=True),
            ConfigField("cloud", "Cloud", kind="select", default="Commercial", options=tuple(LOGIN)),
            ConfigField("resolve_ips", "Look up device IPs (Machine.Read.All)", kind="bool", default=True),
        ),
        default_field_map={
            "hostname": "deviceName",
            "ip_address": "lastIpAddress",
            "os": "osPlatform",
            "resource_id": "deviceId",
            "business_unit": "rbacGroupName",
            "detection_date": "firstSeenTimestamp",
            "source_ref": "id",
        },
        prerequisites=(
            "Entra ID app registration with application permission WindowsDefenderATP → Vulnerability.Read.All "
            "(and Machine.Read.All for device IPs), admin consent granted",
            "Client secret (or rotate one) — stored encrypted",
        ),
        docs="integrations/defender/",
        rate=(30, 60.0),
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _token(self) -> tuple[str, int]:
        cloud = self.config.get("cloud") or "Commercial"
        tenant = str(self.config.get("tenant_id") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,99}", tenant):
            raise ConnectorError("Tenant ID must be the directory GUID or a verified domain")
        resp = self.client.request(
            "POST",
            f"{LOGIN[cloud]}/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.config["client_id"],
                "client_secret": self.secrets.get("client_secret", ""),
                "scope": SCOPE[cloud],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body = json_body(resp, "Microsoft Entra ID")
        if not body.get("access_token"):
            raise ConnectorError("Entra ID did not return an access token — check tenant, client ID and secret")
        return body["access_token"], int(body.get("expires_in", 3599))

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        token = self._tokens.get(self._token)
        resp = self.client.request("GET", url, params=params, headers={"Authorization": f"Bearer {token}"})
        return json_body(resp, "Microsoft Defender")

    def test_connection(self) -> str:
        self._get(self.url("/api/vulnerabilities"), {"$top": 1})
        return "Authenticated to Microsoft Defender and read vulnerabilities"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        safe = cve_id.replace("'", "")
        url: str | None = self.url("/api/machines/SoftwareVulnerabilitiesByMachine")
        params: dict[str, Any] | None = {"$filter": f"cveId eq '{safe}'"}
        seen: dict[str, dict[str, Any]] = {}
        base_host = (urlsplit(self.base_url).hostname or "").lower()
        for _ in range(MAX_PAGES):
            body = self._get(url, params)  # type: ignore[arg-type]
            for row in body.get("value") or []:
                dev = row.get("deviceId") or row.get("id")
                if dev not in seen:  # one row per device × software; keep one per device
                    seen[dev] = row
            url, params = body.get("@odata.nextLink"), None
            if not url:
                break
            if not host_matches((urlsplit(url).hostname or "").lower(), (base_host,)):
                raise ConnectorError("Defender pagination link points to another host — refusing")
        else:
            raise ConnectorError("Defender pagination did not terminate")
        resolve = self.config.get("resolve_ips", True)
        for i, row in enumerate(seen.values()):
            if resolve and i < 200 and row.get("deviceId"):
                try:
                    m = self._get(self.url(f"/api/machines/{row['deviceId']}"))
                    row.setdefault("lastIpAddress", m.get("lastIpAddress"))
                    row["osPlatform"] = row.get("osPlatform") or m.get("osPlatform")
                except Exception:  # noqa: BLE001 - IP lookup is best-effort (needs Machine.Read.All)
                    resolve = False
            yield row

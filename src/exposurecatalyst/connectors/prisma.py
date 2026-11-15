"""Prisma Cloud Compute (CWPP) — ``GET /api/v1/stats/vulnerabilities/impacted-resources?cve=<CVE>``.

Returns the hosts and deployed images (with their running containers) impacted by the CVE. Auth: access key
→ ``POST /api/v1/authenticate`` → bearer token (valid ~1 h). The base URL is the Compute console path
(Runtime Security → System → Utilities → Path to Console), e.g. ``https://us-east1.cloud.twistlock.com/us-1-23``.
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

PAGE = 250
MAX_PAGES = 200


@register
class PrismaCloudConnector(Connector):
    spec = ConnectorSpec(
        kind="prisma_cloud",
        label="Prisma Cloud",
        vendor="Prisma Cloud (Compute / CWPP)",
        description="Hosts, images and running containers impacted by the CVE in Prisma Cloud Compute.",
        host_patterns=("*.cloud.twistlock.com", "*.prismacloud.io"),
        base_url_example="https://us-east1.cloud.twistlock.com/us-1-111111111",
        fields=(
            ConfigField("access_key", "Access key ID", required=True),
            ConfigField("secret_key", "Secret key", kind="secret", required=True),
            ConfigField("collections", "Collections (optional)", default="", help="Comma-separated collection names"),
            ConfigField("include_images", "Include images / containers", kind="bool", default=True),
        ),
        default_field_map={
            "hostname": "host",
            "resource_id": "resource_id",
            "environment": "collection",
            "source_ref": "resource_id",
        },
        prerequisites=(
            "Prisma Cloud access key for a role with Vulnerabilities (Monitor) read permission",
            "Compute console path (Runtime Security → System → Utilities → Path to Console)",
        ),
        docs="integrations/prisma-cloud/",
        rate=(10, 1.0),
        category="Cloud security (CNAPP)",
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _token(self) -> tuple[str, int]:
        resp = self.client.request(
            "POST",
            self.url("/api/v1/authenticate"),
            json={"username": self.config["access_key"], "password": self.secrets.get("secret_key", "")},
        )
        body = json_body(resp, "Prisma Cloud")
        if not body.get("token"):
            raise ConnectorError("Prisma Cloud did not return a token — check the access key")
        return body["token"], 3000

    def _get(self, path: str, params: dict[str, Any]) -> Any:
        token = self._tokens.get(self._token)
        resp = self.client.request("GET", self.url(path), params=params, headers={"Authorization": f"Bearer {token}"})
        return json_body(resp, "Prisma Cloud")

    def test_connection(self) -> str:
        self._get("/api/v1/stats/vulnerabilities", {"limit": 1})
        return "Authenticated to Prisma Cloud Compute and read vulnerability stats"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        params: dict[str, Any] = {"cve": cve_id, "limit": PAGE, "offset": 0}
        if self.config.get("collections"):
            params["collections"] = self.config["collections"]
        seen: set[tuple] = set()
        for _ in range(MAX_PAGES):
            body = self._get("/api/v1/stats/vulnerabilities/impacted-resources", params) or {}
            hosts = body.get("hosts") or []
            images = body.get("images") or [] if self.config.get("include_images", True) else []
            for h in hosts:
                key = ("host", h.get("resourceID"))
                if key not in seen:
                    seen.add(key)
                    yield {"type": "host", "host": h.get("resourceID"), "resource_id": h.get("resourceID")}
            for img in images:
                containers = img.get("containers") or [{}]
                for c in containers:
                    key = ("image", img.get("resourceID"), c.get("host"), c.get("container"))
                    if key in seen:
                        continue
                    seen.add(key)
                    yield {
                        "type": "container" if c.get("container") else "image",
                        "host": c.get("host"),
                        "resource_id": c.get("container") or img.get("resourceID"),
                        "image": img.get("resourceID"),
                    }
            if len(hosts) < PAGE and len(images) < PAGE:
                return
            params["offset"] += PAGE
        raise ConnectorError("Prisma Cloud pagination did not terminate")

"""Configurable REST connector used for Zafran and ArmorCode (and a template for similar tools).

The vendor endpoint path, CVE filter parameter, results key and pagination style are settings, so a tenant
whose API version differs from the defaults can be adapted without code changes. Defaults follow the
vendors' documented patterns but must be confirmed against your tenant's API reference (see the guides).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from exposurecatalyst.connectors.base import ConfigField, Connector, ConnectorError, ConnectorSpec, get_path, register

MAX_PAGES = 1000


def _rest_fields(
    path: str,
    cve_param: str,
    results_key: str,
    pagination: str,
    page_param: str,
    next_key: str,
    test_path: str,
    auth_header: str,
    auth_prefix: str,
) -> tuple[ConfigField, ...]:
    return (
        ConfigField("api_token", "API key / token", kind="secret", required=True),
        ConfigField("auth_header", "Auth header", default=auth_header),
        ConfigField("auth_prefix", "Auth value prefix", default=auth_prefix, help="e.g. 'Bearer ' (note the space)"),
        ConfigField("findings_path", "Findings endpoint path", default=path),
        ConfigField("cve_param", "CVE filter parameter", default=cve_param),
        ConfigField("method", "HTTP method", kind="select", default="GET", options=("GET", "POST")),
        ConfigField("results_key", "Results key (dotted path)", default=results_key),
        ConfigField("pagination", "Pagination", kind="select", default=pagination, options=("cursor", "page", "none")),
        ConfigField("page_param", "Page / cursor parameter", default=page_param),
        ConfigField("next_key", "Next-cursor / total-pages key", default=next_key),
        ConfigField("page_size", "Page size", kind="number", default=500),
        ConfigField("test_path", "Connection test path", default=test_path),
    )


class RestConnector(Connector):
    def _call(self, path: str, params: dict[str, Any]) -> Any:
        headers = {
            self.config["auth_header"]: f"{self.config.get('auth_prefix') or ''}{self.secrets.get('api_token', '')}"
        }
        if (self.config.get("method") or "GET") == "POST":
            resp = self.client.request("POST", self.url(path), json=params, headers=headers)
        else:
            resp = self.client.request("GET", self.url(path), params=params, headers=headers)
        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectorError(f"{self.spec.vendor} returned non-JSON from {path}") from exc

    def test_connection(self) -> str:
        self._call(self.config.get("test_path") or self.config["findings_path"], {"limit": 1})
        return f"Connected to {self.spec.vendor}"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        mode = self.config.get("pagination") or "cursor"
        size = int(self.config.get("page_size") or 500)
        params: dict[str, Any] = {self.config["cve_param"]: cve_id, "limit": size, "size": size}
        page = 0
        for _ in range(MAX_PAGES):
            body = self._call(self.config["findings_path"], params)
            items = get_path(body, self.config["results_key"], join=False) if self.config.get("results_key") else body
            items = items or []
            if not isinstance(items, list):
                raise ConnectorError(f"results key '{self.config['results_key']}' is not a list")
            yield from (i for i in items if isinstance(i, dict))
            if mode == "none" or not items:
                return
            if mode == "cursor":
                nxt = body.get(self.config["next_key"]) if isinstance(body, dict) else None
                if not nxt:
                    return
                params[self.config["page_param"]] = nxt
            else:
                page += 1
                total_pages = body.get(self.config["next_key"]) if isinstance(body, dict) else None
                if (isinstance(total_pages, int) and page >= total_pages) or len(items) < size:
                    return
                params[self.config["page_param"]] = page
        raise ConnectorError("pagination did not terminate")


@register
class ZafranConnector(RestConnector):
    spec = ConnectorSpec(
        kind="zafran",
        label="Zafran",
        vendor="Zafran",
        description="Exploitable-exposure findings from Zafran's threat exposure platform.",
        host_patterns=("*.zafran.io",),
        base_url_example="https://api.zafran.io",
        fields=_rest_fields(
            "/api/v1/findings",
            "cve",
            "data",
            "cursor",
            "cursor",
            "next_cursor",
            "/api/v1/findings",
            "Authorization",
            "Bearer ",
        ),
        default_field_map={
            "hostname": "asset.hostname",
            "ip_address": "asset.ip_address",
            "os": "asset.os",
            "cloud_account": "asset.cloud_account_id",
            "resource_id": "asset.cloud_resource_id",
            "owner": "asset.owner",
            "business_unit": "asset.business_unit",
            "environment": "asset.environment",
            "detection_date": "first_seen",
            "source_ref": "id",
        },
        prerequisites=(
            "Zafran API token with read access to findings/assets (Settings → API)",
            "Your tenant's API base URL",
            "Confirm the findings endpoint and fields in Zafran's API reference",
        ),
        docs="integrations/zafran/",
        rate=(10, 1.0),
    )


@register
class ArmorCodeConnector(RestConnector):
    spec = ConnectorSpec(
        kind="armorcode",
        label="ArmorCode",
        vendor="ArmorCode",
        description="Aggregated findings from ArmorCode's ASPM / unified vulnerability management.",
        host_patterns=("*.armorcode.com", "*.armorcode.io", "*.armorcode.ai"),
        base_url_example="https://app.armorcode.com",
        fields=_rest_fields(
            "/api/findings", "cve", "content", "page", "page", "totalPages", "/api/findings", "Authorization", "Bearer "
        ),
        default_field_map={
            "hostname": "asset.name",
            "ip_address": "asset.ipAddress",
            "os": "asset.os",
            "cloud_account": "asset.cloudAccountId",
            "resource_id": "asset.resourceId",
            "owner": "owner",
            "business_unit": "businessUnit",
            "environment": "environment",
            "detection_date": "firstSeenDate",
            "source_ref": "id",
        },
        prerequisites=(
            "ArmorCode API key (Manage → Integrations → ArmorCode API) with read-only findings scope",
            "Confirm the findings endpoint, filter parameter and fields in ArmorCode's API docs",
        ),
        docs="integrations/armorcode/",
        rate=(10, 1.0),
    )

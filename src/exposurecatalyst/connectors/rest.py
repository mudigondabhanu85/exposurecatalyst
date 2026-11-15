"""Configurable REST connector: Zafran, ArmorCode, Brinqa, Vulcan, Nucleus, XM Cyber and Orca.

These platforms' API references are tenant-gated, so the endpoint path, CVE filter, request body, results key
and pagination style are settings: a tenant whose API differs from the defaults is adapted without code
changes. Defaults follow each vendor's usual pattern and must be confirmed against your tenant's API reference
(the catalog marks them ``api_status="confirm"``).

* ``{name}`` in the endpoint path is replaced with the integration setting of that name (e.g. ``{project_id}``).
* For POST, *Request body (JSON)* is a template: string values ``"{{cve}}"`` / ``"{{limit}}"`` are replaced
  with the CVE ID and page size; without a template the filter parameters are sent as the JSON body.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from exposurecatalyst.connectors.base import (
    ConfigField,
    Connector,
    ConnectorError,
    ConnectorSpec,
    get_path,
    json_body,
    register,
)

MAX_PAGES = 1000
PATH_VAR = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


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
    *,
    method: str = "GET",
    body: str = "",
    extra: tuple[ConfigField, ...] = (),
    page_size: int = 500,
) -> tuple[ConfigField, ...]:
    return (
        ConfigField("api_token", "API key / token", kind="secret", required=True),
        *extra,
        ConfigField("auth_header", "Auth header", default=auth_header),
        ConfigField("auth_prefix", "Auth value prefix", default=auth_prefix, help="e.g. 'Bearer ' (note the space)"),
        ConfigField("findings_path", "Findings endpoint path", default=path, help="{setting} placeholders allowed"),
        ConfigField(
            "cve_param",
            "CVE filter parameter",
            default=cve_param,
            help="Query parameter (GET, or POST without a body template)",
        ),
        ConfigField("method", "HTTP method", kind="select", default=method, options=("GET", "POST")),
        ConfigField(
            "body_template", "Request body (JSON, POST)", default=body, help='"{{cve}}" and "{{limit}}" are substituted'
        ),
        ConfigField("results_key", "Results key (dotted path)", default=results_key),
        ConfigField(
            "pagination", "Pagination", kind="select", default=pagination, options=("cursor", "page", "offset", "none")
        ),
        ConfigField("page_param", "Page / cursor / offset parameter", default=page_param),
        ConfigField("next_key", "Next-cursor / total-pages key (dotted)", default=next_key),
        ConfigField("page_size", "Page size", kind="number", default=page_size),
        ConfigField("test_path", "Connection test path", default=test_path),
    )


def _substitute(node: Any, values: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        return {k: _substitute(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, values) for v in node]
    if isinstance(node, str):
        m = re.fullmatch(r"\{\{(\w+)\}\}", node)
        if m and m.group(1) in values:
            return values[m.group(1)]
        return re.sub(r"\{\{(\w+)\}\}", lambda mm: str(values.get(mm.group(1), mm.group(0))), node)
    return node


class RestConnector(Connector):
    def _path(self, template: str) -> str:
        def repl(m: re.Match) -> str:
            v = self.config.get(m.group(1))
            if v in (None, ""):
                raise ConnectorError(f"setting '{m.group(1)}' is required by the endpoint path")
            return quote(str(v), safe="")

        return PATH_VAR.sub(repl, template)

    def _headers(self) -> dict[str, str]:
        return {
            self.config["auth_header"]: f"{self.config.get('auth_prefix') or ''}{self.secrets.get('api_token', '')}"
        }

    def _body(self, cve_id: str, size: int) -> dict[str, Any] | None:
        tpl = (self.config.get("body_template") or "").strip()
        if not tpl:
            return None
        try:
            parsed = json.loads(tpl)
        except ValueError as exc:
            raise ConnectorError("Request body template is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ConnectorError("Request body template must be a JSON object")
        return _substitute(parsed, {"cve": cve_id, "limit": size})

    def _call(self, path: str, params: dict[str, Any], body: dict[str, Any] | None = None) -> Any:
        url = self.url(self._path(path))
        if (self.config.get("method") or "GET") == "POST":
            if body is None:
                resp = self.client.request("POST", url, json=params, headers=self._headers())
            else:
                resp = self.client.request("POST", url, params=params, json=body, headers=self._headers())
        else:
            resp = self.client.request("GET", url, params=params, headers=self._headers())
        return json_body(resp, self.spec.vendor)

    def test_connection(self) -> str:
        path = self.config.get("test_path") or self.config["findings_path"]
        if (self.config.get("method") or "GET") == "POST" and path == self.config["findings_path"]:
            self._call(path, {}, self._body("CVE-1999-0001", 1) or {"limit": 1})
        else:
            self.client.request("GET", self.url(self._path(path)), params={"limit": 1}, headers=self._headers())
        return f"Connected to {self.spec.vendor}"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        mode = self.config.get("pagination") or "cursor"
        size = int(self.config.get("page_size") or 500)
        body = self._body(cve_id, size)
        params: dict[str, Any] = (
            {"limit": size} if body is not None else {self.config["cve_param"]: cve_id, "limit": size, "size": size}
        )
        page = offset = 0
        target = body if body is not None else params  # POST templates paginate inside the body
        for _ in range(MAX_PAGES):
            data = self._call(self.config["findings_path"], params, body)
            items = get_path(data, self.config["results_key"], join=False) if self.config.get("results_key") else data
            items = items or []
            if not isinstance(items, list):
                raise ConnectorError(f"results key '{self.config['results_key']}' is not a list")
            yield from (i for i in items if isinstance(i, dict))
            if mode == "none" or not items:
                return
            nxt = get_path(data, self.config.get("next_key") or "", join=False) if isinstance(data, dict) else None
            if mode == "cursor":
                if not nxt:
                    return
                target[self.config["page_param"]] = nxt
            elif mode == "offset":
                offset += len(items)
                if len(items) < size or (isinstance(nxt, int) and offset >= nxt):
                    return
                target[self.config["page_param"]] = offset
            else:
                page += 1
                if (isinstance(nxt, int) and page >= nxt) or len(items) < size:
                    return
                target[self.config["page_param"]] = page
        raise ConnectorError("pagination did not terminate")


def _spec(**kw: Any) -> ConnectorSpec:
    return ConnectorSpec(api_status="confirm", rate=(10, 1.0), **kw)


@register
class ZafranConnector(RestConnector):
    spec = _spec(
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
        category="Exposure management (CTEM / RBVM)",
    )


@register
class ArmorCodeConnector(RestConnector):
    spec = _spec(
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
        category="Exposure management (CTEM / RBVM)",
    )


@register
class BrinqaConnector(RestConnector):
    spec = _spec(
        kind="brinqa",
        label="Brinqa",
        vendor="Brinqa",
        description="Unified vulnerability findings and their assets from the Brinqa risk platform.",
        host_patterns=("*.brinqa.net", "*.brinqa.com"),
        base_url_example="https://example.brinqa.net",
        fields=_rest_fields(
            "/api/caasm/model/vulnerabilities/",
            "cveIds",
            "data",
            "offset",
            "skip",
            "",
            "/api/caasm/model/assets/",
            "Authorization",
            "Bearer ",
            method="POST",
            page_size=200,
            body='{"filter": "cveIds = \\"{{cve}}\\" AND status != \\"Closed\\"", "limit": "{{limit}}", '
            '"fields": ["uid", "targets", "firstFound", "status"]}',
        ),
        default_field_map={
            "hostname": "targets.0.hostnames.0",
            "ip_address": "targets.0.ipAddresses.0",
            "os": "targets.0.operatingSystem",
            "cloud_account": "targets.0.cloudAccountId",
            "resource_id": "targets.0.uid",
            "owner": "targets.0.owner",
            "business_unit": "targets.0.businessUnit",
            "environment": "targets.0.environment",
            "detection_date": "firstFound",
            "source_ref": "uid",
        },
        prerequisites=(
            "Brinqa API token for a read-only service user (Administration → API access)",
            "Confirm the data-model endpoint and BQL filter in your Brinqa API reference",
        ),
        docs="integrations/brinqa/",
        category="Exposure management (CTEM / RBVM)",
    )


@register
class VulcanConnector(RestConnector):
    spec = _spec(
        kind="vulcan",
        label="Vulcan",
        vendor="Vulcan Cyber",
        description="Vulnerability instances and assets consolidated by Vulcan Cyber (Tenable Exposure "
        "Management for Vulcan).",
        host_patterns=("*.vulcancyber.com", "*.vulcan.io"),
        base_url_example="https://example.vulcancyber.com",
        fields=_rest_fields(
            "/api/v1/vulnerabilities",
            "cve",
            "data",
            "page",
            "page",
            "total_pages",
            "/api/v1/assets",
            "Authorization",
            "Bearer ",
        ),
        default_field_map={
            "hostname": "asset.hostname",
            "ip_address": "asset.ip_address",
            "os": "asset.os",
            "cloud_account": "asset.cloud_account",
            "resource_id": "asset.external_id",
            "owner": "asset.owners.0",
            "business_unit": "asset.business_group",
            "environment": "asset.environment",
            "detection_date": "first_seen",
            "source_ref": "id",
        },
        prerequisites=(
            "Vulcan API token (Settings → API Tokens) for a read-only user",
            "Confirm the vulnerabilities endpoint and CVE filter in Vulcan's API reference",
        ),
        docs="integrations/vulcan/",
        category="Exposure management (CTEM / RBVM)",
    )


@register
class NucleusConnector(RestConnector):
    spec = _spec(
        kind="nucleus",
        label="Nucleus",
        vendor="Nucleus Security",
        description="Active findings for a CVE in a Nucleus project, with their asset instances.",
        host_patterns=("*.nucleussec.com",),
        base_url_example="https://example.nucleussec.com",
        fields=_rest_fields(
            "/nucleus/api/projects/{project_id}/findings/search",
            "finding_cve",
            "",
            "offset",
            "start",
            "",
            "/nucleus/api/projects/{project_id}",
            "x-apikey",
            "",
            method="POST",
            page_size=100,
            body='{"finding_cve": "{{cve}}", "finding_status": "Active"}',
            extra=(ConfigField("project_id", "Project ID", required=True, help="Numeric ID from the project URL"),),
        ),
        default_field_map={
            "hostname": "asset_name",
            "ip_address": "ip_address",
            "os": "operating_system_name",
            "owner": "asset_owner",
            "business_unit": "asset_groups",
            "environment": "asset_environment",
            "detection_date": "finding_discovered",
            "source_ref": "finding_number",
        },
        prerequisites=(
            "Nucleus API key for a user with View Assets (projectassets-read) on the project",
            "Project ID; confirm the findings-search body in Nucleus → View API Docs",
        ),
        docs="integrations/nucleus/",
        category="Exposure management (CTEM / RBVM)",
    )


@register
class XmCyberConnector(RestConnector):
    spec = _spec(
        kind="xmcyber",
        label="XM Cyber",
        vendor="XM Cyber",
        description="Entities exposed by a CVE in XM Cyber attack-path analysis (choke points and critical "
        "assets included).",
        host_patterns=("*.clients.xmcyber.com", "*.xmcyber.com"),
        base_url_example="https://example.clients.xmcyber.com",
        fields=_rest_fields(
            "/api/systemReport/entities",
            "cve",
            "data",
            "page",
            "page",
            "paging.totalPages",
            "/api/systemReport/entities",
            "X-Api-Key",
            "",
            page_size=100,
        ),
        default_field_map={
            "hostname": "name",
            "ip_address": "ipAddresses.0",
            "os": "os.name",
            "cloud_account": "accountId",
            "resource_id": "entityId",
            "business_unit": "labels",
            "environment": "environment",
            "source_ref": "entityId",
        },
        prerequisites=(
            "XM Cyber API key (Settings → API Keys) with read access",
            "Confirm the entity endpoint and CVE filter parameter in XM Cyber's API reference",
        ),
        docs="integrations/xm-cyber/",
        category="Exposure management (CTEM / RBVM)",
    )


@register
class OrcaConnector(RestConnector):
    spec = _spec(
        kind="orca",
        label="Orca",
        vendor="Orca Security",
        description="Cloud assets with the CVE, from Orca's agentless side-scanning (serving-layer query API).",
        host_patterns=("*.orcasecurity.io",),
        base_url_example="https://api.orcasecurity.io",
        regions=(
            ("US", "https://api.orcasecurity.io"),
            ("EU", "https://app.eu.orcasecurity.io"),
            ("AU", "https://app.au.orcasecurity.io"),
            ("IL", "https://app.il.orcasecurity.io"),
            ("IN", "https://app.in.orcasecurity.io"),
        ),
        fields=_rest_fields(
            "/api/serving-layer/query",
            "",
            "data",
            "offset",
            "start_at_index",
            "total_items",
            "/api/user/session",
            "Authorization",
            "Token ",
            method="POST",
            page_size=500,
            body='{"query": {"models": ["Vulnerability"], "type": "object_set", "with": {"type": "operation", '
            '"operator": "and", "values": [{"key": "CveId", "values": ["{{cve}}"], "type": "str", '
            '"operator": "in"}]}}, "limit": "{{limit}}", "get_results_and_count": true}',
        ),
        default_field_map={
            "hostname": "data.Asset.name",
            "ip_address": "data.Asset.data.PrivateIps.0",
            "os": "data.Asset.data.OsDistribution",
            "cloud_account": "data.CloudAccount.name",
            "resource_id": "data.Asset.data.AssetUniqueId",
            "environment": "data.Asset.data.Tags.environment",
            "detection_date": "data.CreatedAt",
            "source_ref": "id",
        },
        prerequisites=(
            "Orca API token (Settings → Users & Permissions → API) with a read-only role",
            "Region base URL; confirm the serving-layer query model in Orca's API reference",
        ),
        docs="integrations/orca/",
        category="Cloud security (CNAPP)",
    )

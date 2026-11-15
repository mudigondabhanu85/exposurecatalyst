"""Mend.io (SCA) — Platform API 3.0.

Login: ``POST /api/v3.0/login`` (email + user key + org UUID) → refresh token →
``POST /api/v3.0/login/accessToken`` → JWT. Mend has no organization-wide CVE search in the API, so the
connector lists projects (``GET /api/v3.0/orgs/{org}/projects``) and reads each project's security findings
(``GET /api/v3.0/projects/{project}/dependencies/findings/security?search=vulnerabilityName:equals:<CVE>``),
bounded by *Max projects*.
"""

from __future__ import annotations

import re
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

PAGE = 1000
UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


@register
class MendConnector(Connector):
    spec = ConnectorSpec(
        kind="mend",
        label="Mend",
        vendor="Mend.io",
        description="Projects with a vulnerable open-source dependency for the CVE (Mend SCA).",
        host_patterns=(
            "api-saas.mend.io",
            "api-saas-eu.mend.io",
            "api-app-eu.mend.io",
            "api-saas-sg.mend.io",
            "*.mend.io",
            "*.whitesourcesoftware.com",
        ),
        base_url_example="https://api-saas.mend.io",
        regions=(
            ("US", "https://api-saas.mend.io"),
            ("EU", "https://api-saas-eu.mend.io"),
            ("APAC", "https://api-saas-sg.mend.io"),
        ),
        fields=(
            ConfigField("email", "Service user email", required=True),
            ConfigField("user_key", "User key", kind="secret", required=True),
            ConfigField("org_uuid", "Organization UUID", required=True),
            ConfigField("max_projects", "Max projects to check", kind="number", default=500),
        ),
        default_field_map={
            "hostname": "project.name",
            "resource_id": "project.uuid",
            "os": "component.name",
            "business_unit": "project.applicationName",
            "detection_date": "createdAt",
            "source_ref": "uuid",
        },
        prerequisites=(
            "Mend service user with the Organization Viewer role and its user key",
            "Organization UUID (Settings → Integrate)",
        ),
        docs="integrations/mend/",
        rate=(5, 1.0),
        category="Application security (SCA / code)",
        api_status="confirm",
    )

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokens = TokenCache()

    def _org(self) -> str:
        org = str(self.config.get("org_uuid") or "")
        if not UUID.match(org):
            raise ConnectorError("Organization UUID is not a UUID")
        return org

    def _token(self) -> tuple[str, int]:
        resp = self.client.request(
            "POST",
            self.url("/api/v3.0/login"),
            json={"email": self.config["email"], "userKey": self.secrets.get("user_key", ""), "orgUuid": self._org()},
        )
        refresh = (json_body(resp, "Mend").get("response") or {}).get("refreshToken")
        if not refresh:
            raise ConnectorError("Mend login failed — check email, user key and organization UUID")
        resp = self.client.request(
            "POST", self.url("/api/v3.0/login/accessToken"), headers={"wss-refresh-token": refresh}
        )
        body = json_body(resp, "Mend").get("response") or {}
        if not body.get("jwtToken"):
            raise ConnectorError("Mend did not return an access token")
        return body["jwtToken"], int(int(body.get("jwtTTL") or 1_800_000) / 1000)

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        token = self._tokens.get(self._token)
        resp = self.client.request("GET", self.url(path), params=params, headers={"Authorization": f"Bearer {token}"})
        return json_body(resp, "Mend")

    def test_connection(self) -> str:
        self._get(f"/api/v3.0/orgs/{self._org()}/projects", {"limit": 1})
        return "Connected to Mend and listed projects"

    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        cap, cursor, projects = int(self.config.get("max_projects") or 500), None, []
        while len(projects) < cap:
            params: dict[str, Any] = {"limit": min(PAGE, cap - len(projects))}
            if cursor:
                params["cursor"] = cursor
            body = self._get(f"/api/v3.0/orgs/{self._org()}/projects", params)
            rows = body.get("response") or []
            projects += rows
            cursor = ((body.get("additionalData") or {}).get("paging") or {}).get("next")
            if not rows or not cursor:
                break
        for p in projects:
            if not p.get("uuid"):
                continue
            body = self._get(
                f"/api/v3.0/projects/{p['uuid']}/dependencies/findings/security",
                {"search": f"vulnerabilityName:equals:{cve_id}", "limit": PAGE},
            )
            for f in body.get("response") or []:
                name = (f.get("vulnerability") or {}).get("name")
                if name and str(name).upper() != cve_id:
                    continue
                if (f.get("findingInfo") or {}).get("status") in ("IGNORED", "RESOLVED"):
                    continue
                yield {**f, "project": p}

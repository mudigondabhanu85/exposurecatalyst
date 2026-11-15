"""Action connectors: create a ticket (Jira, ServiceNow ITSM) or post a notification (Slack, Microsoft Teams)
for an advisory. They never answer CVE asset questions (``capabilities`` excludes ``assets_for_cve``).

Triggered from the advisory page ("Create ticket / Share") by users with ``advisory:send``; every delivery is
recorded in ``advisory_actions`` and the audit log. Slack / Teams can also be alert channels (Alerts).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from exposurecatalyst.connectors.base import (
    ActionConnector,
    ConfigField,
    ConnectorError,
    ConnectorSpec,
    json_body,
    register,
)
from exposurecatalyst.security.ssrf import host_matches

SEV_PRIORITY = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
SEV_IMPACT = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "2", "LOW": "3"}  # ServiceNow impact/urgency 1-3
EMPTY_MAP: dict[str, str] = {}
TEAMS_HOSTS = (
    "*.webhook.office.com",
    "*.logic.azure.com",
    "*.powerplatform.com",
    "*.environment.api.powerplatform.com",
)


def text_summary(item: dict[str, Any], *, limit: int = 3000) -> str:
    lines = [
        f"{item['advisory_id']} — {item['cve_id']} ({item['severity']})",
        item.get("title") or "",
        "",
        f"Affected assets: {item.get('asset_count', 0)} across {', '.join(item.get('sources') or []) or 'no sources'}",
    ]
    if item.get("sla_due_date"):
        lines.append(f"Remediation due: {item['sla_due_date']}")
    for label, key in (("Summary", "summary"), ("Remediation", "remediation"), ("Workaround", "workaround")):
        if item.get(key):
            lines += ["", f"{label}:", str(item[key])]
    lines += ["", f"Advisory: {item['url']}"]
    return "\n".join(lines)[:limit]


def check_webhook(url: str, hosts: tuple[str, ...], name: str) -> str:
    parts = urlsplit(url or "")
    if parts.scheme != "https" or not host_matches((parts.hostname or "").lower(), hosts):
        raise ConnectorError(f"{name} webhook must be an https URL on {', '.join(hosts)}")
    return url


@register
class JiraConnector(ActionConnector):
    spec = ConnectorSpec(
        kind="jira",
        label="Jira",
        vendor="Jira (Cloud / Data Center)",
        description="Create a Jira issue from an advisory, with severity-based priority and the affected-asset "
        "summary.",
        host_patterns=("*.atlassian.net", "*.jira.com"),
        base_url_example="https://example.atlassian.net",
        fields=(
            ConfigField("deployment", "Deployment", kind="select", default="Cloud", options=("Cloud", "Data Center")),
            ConfigField("email", "Account email (Cloud)", default="", help="Blank for Data Center (uses a PAT)"),
            ConfigField("api_token", "API token (Cloud) / personal access token (DC)", kind="secret", required=True),
            ConfigField("project_key", "Project key", required=True),
            ConfigField("issue_type", "Issue type", default="Task"),
            ConfigField("labels", "Labels", default="exposurecatalyst,vulnerability", help="Comma-separated"),
            ConfigField("set_priority", "Set priority from severity", kind="bool", default=True),
        ),
        default_field_map=EMPTY_MAP,
        prerequisites=(
            "Jira user (or service account) with Browse + Create Issues on the project",
            "Cloud: API token from id.atlassian.com; Data Center: personal access token",
            "Self-managed Data Center hosts must be in EXCAT_EGRESS_ALLOWLIST",
        ),
        docs="integrations/jira/",
        rate=(5, 1.0),
        capabilities=("create_ticket",),
        category="Ticketing",
    )

    def _cloud(self) -> bool:
        return (self.config.get("deployment") or "Cloud") == "Cloud"

    def _auth(self) -> dict[str, Any]:
        token = self.secrets.get("api_token", "")
        if self._cloud():
            if not self.config.get("email"):
                raise ConnectorError("Account email is required for Jira Cloud")
            return {"auth": (self.config["email"], token)}
        return {"headers": {"Authorization": f"Bearer {token}"}}

    def _api(self) -> str:
        return "/rest/api/3" if self._cloud() else "/rest/api/2"

    def test_connection(self) -> str:
        resp = self.client.request(
            "GET", self.url(f"{self._api()}/project/{self.config['project_key']}"), **self._auth()
        )
        proj = json_body(resp, "Jira")
        return f"Connected to Jira; can see project {proj.get('key')} — {proj.get('name')}"

    def deliver(self, item: dict[str, Any]) -> dict[str, Any]:
        text = text_summary(item, limit=30000)
        if self._cloud():  # Atlassian Document Format
            description: Any = {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": para}]}
                    if para
                    else {"type": "paragraph"}
                    for para in text.split("\n")
                ],
            }
        else:
            description = text
        fields: dict[str, Any] = {
            "project": {"key": self.config["project_key"]},
            "issuetype": {"name": self.config.get("issue_type") or "Task"},
            "summary": f"[{item['severity']}] {item['cve_id']}: {(item.get('title') or '')}"[:250],
            "description": description,
            "labels": [x.strip().replace(" ", "-") for x in (self.config.get("labels") or "").split(",") if x.strip()],
        }
        if self.config.get("set_priority", True) and item["severity"] in SEV_PRIORITY:
            fields["priority"] = {"name": SEV_PRIORITY[item["severity"]]}
        if item.get("sla_due_date"):
            fields["duedate"] = str(item["sla_due_date"])
        resp = self.client.request(
            "POST", self.url(f"{self._api()}/issue"), json={"fields": fields}, ok_statuses=(200, 201), **self._auth()
        )
        key = json_body(resp, "Jira").get("key")
        if not key:
            raise ConnectorError("Jira did not return an issue key")
        return {"ref": key, "url": f"{self.base_url}/browse/{key}"}


@register
class ServiceNowItsmConnector(ActionConnector):
    spec = ConnectorSpec(
        kind="servicenow_itsm",
        label="ServiceNow ITSM",
        vendor="ServiceNow ITSM",
        description="Create a ServiceNow incident (or another task table) from an advisory, with impact/urgency "
        "from severity.",
        host_patterns=("*.service-now.com", "*.servicenowservices.com"),
        base_url_example="https://example.service-now.com",
        fields=(
            ConfigField("username", "Integration user", required=True),
            ConfigField("password", "Password", kind="secret", required=True),
            ConfigField(
                "table",
                "Table",
                kind="select",
                default="incident",
                options=("incident", "problem", "sn_vul_vulnerability", "change_request"),
            ),
            ConfigField("assignment_group", "Assignment group (name or sys_id)", default=""),
            ConfigField("category", "Category", default="security"),
        ),
        default_field_map=EMPTY_MAP,
        prerequisites=(
            "Integration user with itil (or the table's create role) and web-service access only",
            "Optional default assignment group",
        ),
        docs="integrations/servicenow-itsm/",
        rate=(10, 1.0),
        capabilities=("create_ticket",),
        category="Ticketing",
    )

    def _auth(self) -> tuple[str, str]:
        return self.config["username"], self.secrets.get("password", "")

    def test_connection(self) -> str:
        table = self.config.get("table") or "incident"
        self.client.request(
            "GET",
            self.url(f"/api/now/table/{table}"),
            params={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
            auth=self._auth(),
        )
        return f"Connected to ServiceNow and read the {table} table"

    def deliver(self, item: dict[str, Any]) -> dict[str, Any]:
        table = self.config.get("table") or "incident"
        sev = SEV_IMPACT.get(item["severity"], "3")
        record = {
            "short_description": f"[{item['severity']}] {item['cve_id']}: {item.get('title') or ''}"[:160],
            "description": text_summary(item, limit=4000),
            "impact": sev,
            "urgency": sev,
            "category": self.config.get("category") or "security",
            "correlation_id": item["advisory_id"],
            "correlation_display": "ExposureCatalyst",
        }
        if self.config.get("assignment_group"):
            record["assignment_group"] = self.config["assignment_group"]
        resp = self.client.request(
            "POST",
            self.url(f"/api/now/table/{table}"),
            json=record,
            auth=self._auth(),
            params={"sysparm_fields": "sys_id,number"},
            ok_statuses=(200, 201),
        )
        res = json_body(resp, "ServiceNow").get("result") or {}
        if not res.get("sys_id"):
            raise ConnectorError("ServiceNow did not return a record")
        return {
            "ref": res.get("number") or res["sys_id"],
            "url": f"{self.base_url}/nav_to.do?uri={table}.do?sys_id={res['sys_id']}",
        }


@register
class SlackConnector(ActionConnector):
    spec = ConnectorSpec(
        kind="slack",
        label="Slack",
        vendor="Slack",
        description="Post advisories to a Slack channel (bot token or incoming webhook).",
        host_patterns=("slack.com", "hooks.slack.com"),
        base_url_example="https://slack.com",
        fixed_base_url="https://slack.com",
        fields=(
            ConfigField(
                "bot_token",
                "Bot token (xoxb-…)",
                kind="secret",
                help="Preferred: scopes chat:write (+ chat:write.public for channels it isn't in)",
            ),
            ConfigField("channel", "Channel ID", default="", help="e.g. C0123456789 (required with a bot token)"),
            ConfigField(
                "webhook_url",
                "…or incoming webhook URL",
                kind="secret",
                help="https://hooks.slack.com/services/…; Test posts a test message",
            ),
        ),
        default_field_map=EMPTY_MAP,
        prerequisites=(
            "A Slack app installed to the workspace with chat:write, and its channel ID — or an incoming webhook",
        ),
        docs="integrations/slack/",
        rate=(1, 1.0),
        capabilities=("notify",),
        category="Notifications",
    )

    def _blocks(self, item: dict[str, Any]) -> dict[str, Any]:
        head = f"*<{item['url']}|{item['advisory_id']}>* · *{item['cve_id']}* · {item['severity']}"
        body = f"{(item.get('title') or '')[:300]}\nAffected assets: *{item.get('asset_count', 0)}*" + (
            f" · Due {item['sla_due_date']}" if item.get("sla_due_date") else ""
        )
        return {
            "text": f"{item['advisory_id']} {item['cve_id']} ({item['severity']})",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": head}},
                {"type": "section", "text": {"type": "mrkdwn", "text": body}},
            ],
        }

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        token = self.secrets.get("bot_token")
        if token:
            if not self.config.get("channel"):
                raise ConnectorError("Channel ID is required with a bot token")
            resp = self.client.request(
                "POST",
                "https://slack.com/api/chat.postMessage",
                json={"channel": self.config["channel"], **payload},
                headers={"Authorization": f"Bearer {token}"},
            )
            body = json_body(resp, "Slack")
            if not body.get("ok"):
                raise ConnectorError(f"Slack error: {body.get('error', 'unknown')}")
            return body
        hook = self.secrets.get("webhook_url")
        if not hook:
            raise ConnectorError("Configure a bot token + channel or an incoming webhook URL")
        self.client.request(
            "POST", check_webhook(hook, ("hooks.slack.com",), "Slack"), json=payload, ok_statuses=(200, 204)
        )
        return {}

    def test_connection(self) -> str:
        token = self.secrets.get("bot_token")
        if token:
            resp = self.client.request(
                "POST", "https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {token}"}
            )
            body = json_body(resp, "Slack")
            if not body.get("ok"):
                raise ConnectorError(f"Slack error: {body.get('error', 'unknown')}")
            return f"Authenticated to Slack workspace {body.get('team')} as {body.get('user')}"
        self._post({"text": "ExposureCatalyst connection test — advisories will be posted here."})
        return "Posted a test message to the Slack webhook"

    def deliver(self, item: dict[str, Any]) -> dict[str, Any]:
        body = self._post(self._blocks(item))
        return {"ref": body.get("ts") or "posted", "url": None}


@register
class TeamsConnector(ActionConnector):
    spec = ConnectorSpec(
        kind="teams",
        label="Microsoft Teams",
        vendor="Microsoft Teams",
        description="Post advisories to a Teams channel as an Adaptive Card (Workflows webhook).",
        host_patterns=TEAMS_HOSTS,
        base_url_example="https://teams.microsoft.com",
        fixed_base_url="https://teams.microsoft.com",
        fields=(
            ConfigField(
                "webhook_url",
                "Workflows webhook URL",
                kind="secret",
                required=True,
                help="Teams → channel → Workflows → 'Post to a channel when a webhook request is "
                "received'; Test posts a test card",
            ),
        ),
        default_field_map=EMPTY_MAP,
        prerequisites=(
            "A Teams Workflows flow 'Post to a channel when a webhook request is received' (Office 365 "
            "connectors are retired)",
        ),
        docs="integrations/teams/",
        rate=(1, 1.0),
        capabilities=("notify",),
        category="Notifications",
    )

    def _card(self, title: str, lines: list[str], url: str | None = None) -> dict[str, Any]:
        content: dict[str, Any] = {
            "type": "AdaptiveCard",
            "version": "1.4",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "body": [
                {"type": "TextBlock", "weight": "Bolder", "size": "Medium", "wrap": True, "text": title},
                *({"type": "TextBlock", "wrap": True, "text": t} for t in lines),
            ],
        }
        if url:
            content["actions"] = [{"type": "Action.OpenUrl", "title": "Open advisory", "url": url}]
        return {
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": content}],
        }

    def _post(self, payload: dict[str, Any]) -> None:
        hook = check_webhook(self.secrets.get("webhook_url", ""), TEAMS_HOSTS, "Teams")
        self.client.request("POST", hook, json=payload, ok_statuses=(200, 202, 204))

    def test_connection(self) -> str:
        self._post(self._card("ExposureCatalyst connection test", ["Advisories will be posted here."]))
        return "Posted a test card to the Teams workflow"

    def deliver(self, item: dict[str, Any]) -> dict[str, Any]:
        lines = [
            (item.get("title") or "")[:300],
            f"Affected assets: **{item.get('asset_count', 0)}**"
            + (f" · Due {item['sla_due_date']}" if item.get("sla_due_date") else ""),
        ]
        self._post(self._card(f"{item['advisory_id']} · {item['cve_id']} · {item['severity']}", lines, item["url"]))
        return {"ref": "posted", "url": None}

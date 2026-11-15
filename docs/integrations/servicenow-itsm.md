# ServiceNow ITSM

Create a ServiceNow incident (or another task table) from an advisory, with impact/urgency from severity.

## Prerequisites

- Integration user with itil (or the table's create role) and web-service access only
- Optional default assignment group

## Setup

1. Settings → Integrations → **ServiceNow ITSM → Set up**.
2. Base URL: your instance.
3. Table (default `incident`), optional assignment group and category. Impact/urgency: CRITICAL→1, HIGH/MEDIUM→2, LOW→3.
4. **Save & test**, then enable. Enabled action integrations appear on approved advisories under **Tickets & sharing**.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.service-now.com` · allowed: `*.service-now.com`, `*.servicenowservices.com` |
| Integration user * |  |
| Password * | encrypted, never shown again |
| Table | default `incident` |
| Assignment group (name or sys_id) |  |
| Category | default `security` |

## How it works

Triggered from the advisory page ("Create ticket / Share") by users with `advisory:send`; every delivery is
recorded in `advisory_actions` and the audit log. Slack / Teams can also be alert channels (Alerts).

Only users with **advisory:send** can create tickets or post, and only for **approved** or **sent** advisories. Each attempt (success or failure) is listed on the advisory and written to the audit log (`advisory.ticket_created` / `advisory.shared`). Action integrations are never queried for affected assets.

## Rate limits

The connector sends at most 10 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 403` | Add the table's create role (e.g. itil) to the integration user |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |

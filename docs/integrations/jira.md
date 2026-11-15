# Jira (Cloud / Data Center)

Create a Jira issue from an advisory, with severity-based priority and the affected-asset summary.

## Prerequisites

- Jira user (or service account) with Browse + Create Issues on the project
- Cloud: API token from id.atlassian.com; Data Center: personal access token
- Self-managed Data Center hosts must be in EXCAT_EGRESS_ALLOWLIST

## Setup

1. Settings → Integrations → **Jira (Cloud / Data Center) → Set up**.
2. Base URL: `https://<site>.atlassian.net` (Cloud) or your Data Center URL (allowlisted).
3. Cloud: account email + API token. Data Center: leave email blank, paste a personal access token.
4. Project key, issue type (default *Task*), labels. *Set priority* maps CRITICAL→Highest, HIGH→High, MEDIUM→Medium, LOW→Low (turn off if your scheme differs).
5. **Save & test**, then enable. Enabled action integrations appear on approved advisories under **Tickets & sharing**.

### Settings

| Setting | Notes |
|---|---|
| Base URL | e.g. `https://example.atlassian.net` · allowed: `*.atlassian.net`, `*.jira.com` |
| Deployment | default `Cloud` |
| Account email (Cloud) | Blank for Data Center (uses a PAT) |
| API token (Cloud) / personal access token (DC) * | encrypted, never shown again |
| Project key * |  |
| Issue type | default `Task` |
| Labels | Comma-separated · default `exposurecatalyst,vulnerability` |
| Set priority from severity | default `True` |

## How it works

Triggered from the advisory page ("Create ticket / Share") by users with `advisory:send`; every delivery is
recorded in `advisory_actions` and the audit log. Slack / Teams can also be alert channels (Alerts).

Only users with **advisory:send** can create tickets or post, and only for **approved** or **sent** advisories. Each attempt (success or failure) is listed on the advisory and written to the audit log (`advisory.ticket_created` / `advisory.shared`). Action integrations are never queried for affected assets.

## Rate limits

The connector sends at most 5 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 400` creating issues | Priority or issue type not in the project's scheme: untick *Set priority* or fix the type |
| `HTTP 404` on Test | Project key wrong, or the user cannot browse it |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |

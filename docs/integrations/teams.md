# Microsoft Teams

Post advisories to a Teams channel as an Adaptive Card (Workflows webhook).

## Prerequisites

- A Teams Workflows flow 'Post to a channel when a webhook request is received' (Office 365 connectors are retired)

## Setup

1. Settings → Integrations → **Microsoft Teams → Set up**.
2. In the channel: **Workflows → Post to a channel when a webhook request is received**, copy the URL.
3. **Test** posts a test card to the channel.
4. **Save & test**, then enable. Enabled action integrations appear on approved advisories under **Tickets & sharing**.

### Settings

| Setting | Notes |
|---|---|
| Workflows webhook URL * | Teams → channel → Workflows → 'Post to a channel when a webhook request is received'; Test posts a test card · encrypted, never shown again |

## How it works

Triggered from the advisory page ("Create ticket / Share") by users with `advisory:send`; every delivery is
recorded in `advisory_actions` and the audit log. Slack / Teams can also be alert channels (Alerts).

Only users with **advisory:send** can create tickets or post, and only for **approved** or **sent** advisories. Each attempt (success or failure) is listed on the advisory and written to the audit log (`advisory.ticket_created` / `advisory.shared`). Action integrations are never queried for affected assets.

## Rate limits

The connector sends at most 1 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `webhook must be an https URL on …` | Use the Workflows URL; legacy Office 365 connector URLs are retired |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |

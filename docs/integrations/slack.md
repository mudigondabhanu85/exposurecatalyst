# Slack

Post advisories to a Slack channel (bot token or incoming webhook).

## Prerequisites

- A Slack app installed to the workspace with chat:write, and its channel ID — or an incoming webhook

## Setup

1. Settings → Integrations → **Slack → Set up**.
2. Preferred: a Slack app bot token (`chat:write`, plus `chat:write.public` for public channels it hasn't joined) and the channel ID. **Test** calls `auth.test` and posts nothing.
3. Alternative: an incoming webhook URL (`https://hooks.slack.com/…`). **Test** posts a test message.
4. **Save & test**, then enable. Enabled action integrations appear on approved advisories under **Tickets & sharing**.

### Settings

| Setting | Notes |
|---|---|
| Bot token (xoxb-…) | Preferred: scopes chat:write (+ chat:write.public for channels it isn't in) · encrypted, never shown again |
| Channel ID | e.g. C0123456789 (required with a bot token) |
| …or incoming webhook URL | https://hooks.slack.com/services/…; Test posts a test message · encrypted, never shown again |

## How it works

Triggered from the advisory page ("Create ticket / Share") by users with `advisory:send`; every delivery is
recorded in `advisory_actions` and the audit log. Slack / Teams can also be alert channels (Alerts).

Only users with **advisory:send** can create tickets or post, and only for **approved** or **sent** advisories. Each attempt (success or failure) is listed on the advisory and written to the audit log (`advisory.ticket_created` / `advisory.shared`). Action integrations are never queried for affected assets.

## Rate limits

The connector sends at most 1 request(s) per 1 s, retries `429`/`5xx` with backoff and honours `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `channel_not_found` / `not_in_channel` | Invite the app to the channel or add chat:write.public |
| `Base URL rejected` | Use the vendor's API host, or allowlist a custom/on-prem host |
| `HTTP 401` / `403` | Check the credential and its read-only role or scopes |

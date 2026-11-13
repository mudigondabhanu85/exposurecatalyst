# Alerts & scheduling

Alert rules notify people when CVEs that matter appear or change. Configure them in **Settings → Alerts &
Scheduling** (`settings:manage`).

## Criteria

All configured criteria must match:

| Criterion | Matches when |
|---|---|
| Severity at least | Headline severity ≥ value |
| CVSS ≥ / EPSS ≥ | Score at or above the threshold (EPSS as 0–1) |
| Newly added to KEV | A `KEV_ADDED` event occurred since the last evaluation |
| Vendor / product watchlist | Any CPE vendor/product contains a listed value (case-insensitive) |
| Keywords | Title or description contains any keyword |
| Affected assets > 0 | Cached integration results report at least one asset. Run *Check now* or *Pull from integrations* to populate them |

At least one criterion is required.

## Evaluation and delivery

- Rules are evaluated **after every scheduler tick** (60 seconds) against CVEs updated since the rule's
  cursor. A new rule starts from "now", so it never floods you with history.
- Each CVE alerts **once per rule**, even if it changes again later.
- **Immediate** mode sends pending matches at most once per *throttle* window (default 60 min).
  **Digest** sends one message every *digest* interval (default 24 h). A message lists up to 50 CVEs, plus
  "and N more".
- **Run now** evaluates immediately and sends pending matches, ignoring throttle.

## Channels

| Channel | Setup |
|---|---|
| Email | Uses [Settings → SMTP](smtp.md). Recipients: addresses, and/or all active users holding selected roles |
| Slack | Incoming webhook URL (`https://hooks.slack.com/services/…`) |
| Microsoft Teams | Workflows (Power Automate) or incoming webhook URL (`*.webhook.office.com`, `*.logic.azure.com`). An Adaptive Card is posted |

Webhook URLs are secrets: they're encrypted at rest, never returned, and must be on the hosts above.
Failures are shown on the rule (*last error*), and one failing channel doesn't block the others.

## Scheduling

| What | Where | Default |
|---|---|---|
| CVE source fetch interval (per source) | Settings → CVE Sources | 60 min (`EXCAT_FETCH_INTERVAL_MINUTES`) |
| Scheduler tick | `EXCAT_SCHEDULER_TICK_SECONDS` | 60 s |
| Integration result cache | `EXCAT_CONNECTOR_CACHE_MINUTES` | 60 min |
| News refresh interval | Security News (Phase 5) | — |

In AWS, the scheduler tick can be triggered by Amazon EventBridge Scheduler. The alert event is also the
`Alert.Triggered` domain event (see [architecture](../architecture/high-level.md)).

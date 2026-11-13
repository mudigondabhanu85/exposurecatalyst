---
id: settings-alerts
title: Settings — Alerts & Scheduling
page: /settings/alerts
permission: settings:manage
summary: Create alert rules that notify by email, Slack or Teams when matching CVEs appear or change.
keywords: [alerts, notifications, slack, teams, email, digest, throttle, watchlist, kev, schedule]
docs: admin-guide/alerts/
---

## What this page is for

Alert rules watch incoming CVE changes and notify people when a CVE matches, for example "critical or newly
KEV-listed CVEs affecting our vendor watchlist".

## How to use it

1. Click **New rule** and give it a name.
2. Set **criteria**. Every criterion you fill in must match: severity, CVSS, EPSS, newly added to KEV,
   vendor/product watchlist, keywords, affected assets > 0.
3. Choose **channels**: email (addresses and/or roles), Slack or Teams (paste the webhook URL).
4. Choose **delivery**: *Immediate*, at most once per throttle window, or *Digest* every N minutes.
5. **Save rule**. Use **Run now** to evaluate immediately and send pending matches.

## Fields and columns

| Column | Meaning |
|---|---|
| Matches (pending) | CVEs this rule has matched in total, and how many are waiting for the next delivery |
| Last sent | Time of the last notification, with the error if a channel failed |

## Required permissions

`settings:manage` (Admin, Super Admin).

## Common errors

- **"Add at least one criterion"**: a rule with no criteria would alert on every CVE.
- **"Email channel needs at least one recipient"**: add addresses or roles.
- **"slack webhook rejected"**: Slack URLs must be on `hooks.slack.com`. Teams URLs must be on
  `*.webhook.office.com`, `*.logic.azure.com` or `*.powerplatform.com`.
- **Nothing arrives**: check *Last sent* and the error; confirm SMTP under Settings → SMTP; check that the
  scheduler is running (CVE Sources page).

## Learn more

See [Alerts & scheduling](../admin-guide/alerts.md).

---
id: settings-subscriptions
title: Threat Intel & News Subscriptions
page: /settings/integrations
permission: integration:manage
summary: Connect paid intel sources (or any REST, RSS or TAXII feed), record licence terms, and control what may appear in emails and be sent to AI.
keywords: [subscriptions, threat intel, recorded future, mandiant, vulncheck, flashpoint, crowdstrike, taxii, stix, rss, licence, license, tlp, redistribution, quota, manual intel, import]
docs: integrations/subscriptions/
---

## What this page is for

Subscriptions bring licensed intelligence into CVE Intelligence and Security News, labelled with its source.
This section appears under Settings → Integrations when `features.subscriptions` is on.

## How to use it

1. **Add a subscription**: pick a vendor preset, a custom REST / RSS / TAXII source, or *Manual* for portal,
   PDF and email subscriptions.
2. Enter the base URL and credentials. For REST sources, check the endpoints and the **field mapping**
   (JSONPath, e.g. `$.data[*]` for results and `$.cve` for the CVE ID).
3. Click **Test & preview**: the first parsed records and the first raw record appear before anything is saved.
4. Fill in the **licence** (owner, tier, seats, API quota, dates, cost center) and the **redistribution**
   controls, then tick **Enabled** and save.

Analysts with `intel:manage` add items manually or import CSV, JSON or STIX bundles from a CVE page (**Add
intel**) or Security News → Subscription intelligence.

## Fields and columns

| Item | Meaning |
|---|---|
| Content in stakeholder emails | Full · Summary only · None — what advisory emails may include from this source |
| Allow sending to external AI providers | Whether this source's content may be added to AI prompts (off by default) |
| Default TLP | TLP for pulled items; TLP:RED never leaves the platform |
| Usage | API calls this period against the quota, items stored, last successful pull |
| Error log | The latest pull failures |

## Required permissions

`integration:manage` to configure; `intel:manage` for manual items, attachments, imports and TLP:RED
visibility; `cve:view` / `news:view` to read intel. Every change is audited.

## Common errors

- **"host … is not allowed"**: the URL (or a pagination link) points outside the subscription's host. Add
  regional or private hosts to `EXCAT_EGRESS_ALLOWLIST`.
- **"the token endpoint did not return an access token"**: wrong client ID or secret, or wrong token URL.
- **"API quota for this period is used up"**: pulls pause until the period resets, or raise the quota.
- **Preview shows 0 records**: check the results path and that `cve_id` maps to something containing a CVE ID.

## Learn more

See the [Subscriptions guide](../integrations/subscriptions.md).

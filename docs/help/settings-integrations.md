---
id: settings-integrations
title: Settings — Integrations
page: /settings/integrations
permission: integration:manage
summary: Connect 24 vulnerability, cloud, AppSec, CAASM and exposure-management tools for affected assets, plus Jira, ServiceNow ITSM, Slack and Teams for advisory tickets and posts.
keywords: [integrations, connectors, qualys, tanium, wiz, zafran, armorcode, servicenow, cmdb, tenable, rapid7, crowdstrike, defender, prisma, orca, snyk, brinqa, kenna, vulcan, axonius, armis, runzero, nucleus, xm cyber, checkmarx, mend, jira, itsm, slack, teams, field mapping, region, test]
docs: integrations/
---

## What this page is for

Integrations answer the question "which of our assets does this CVE affect?". When an analyst clicks
**Check now** on a CVE or **Pull from integrations** on an advisory, every *enabled* integration is queried.
The results fill the asset validation matrix and the Excel attachment.

**Action connectors** (Jira, ServiceNow ITSM, Slack, Microsoft Teams) are different: they are never queried
for assets. Once enabled, they appear on approved advisories under **Tickets & sharing**, where users with
`advisory:send` can create a ticket or post the advisory.

Connectors are grouped by category; use **Filter connectors** to find one. A **Confirm defaults** badge means
the vendor's API reference is not public. Its endpoint, filter and field defaults are editable, so confirm them
against your tenant's API docs, then run **Check now** on a CVE you know is present before enabling.

## How to use it

1. Under **Add a connector**, click **Set up** on a tool. The setup guide on the left lists the prerequisites.
2. Enter a **Name** and pick the **region** (which fills the base URL) or type the tool's **Base URL**. It must
   be the vendor's cloud domain, or a host your admin added to `EXCAT_EGRESS_ALLOWLIST` for self-hosted tools
   (Tenable Security Center, on-prem Axonius, Jira Data Center). Slack and Teams need no base URL.
3. Enter the credentials of a dedicated, read-only service account (for action connectors: an account that can
   only create tickets or post).
4. Click **Save & test**. A green ✓ means authentication and one read-only call succeeded. Testing a Slack or
   Teams **webhook** posts a short test message, because webhooks cannot be checked any other way.
5. Tick **Enabled** in the *Configured* table.
6. Optional: open **Field mapping (advanced)** to change which field of the tool's record feeds hostname, IP,
   owner and so on.

## Fields and columns

| Field | Meaning |
|---|---|
| Status | *Healthy* (last test or sync succeeded), *Failing* (last call failed; hover for the error), *Pending* (never tested, or changed since) |
| Enabled | Only enabled integrations are queried |
| Last test / sync | Last **Save & test**, and last successful CVE lookup |
| Field mapping | Dotted path into the tool's record, e.g. `vulnerableAsset.ipAddresses.0`. `=Production` sets a constant |

## Required permissions

`integration:manage` (Admin, Super Admin). Analysts with `cve:refresh` can run **Check now**, and those with
`advisory:create` can **Pull from integrations**. Creating tickets and posts needs `advisory:send` and an
approved or sent advisory. Every change and test is audited, and credentials never
appear in the audit log.

## Common errors

- **"Base URL rejected: host … is not a known … domain"**: use the vendor's cloud URL, or ask for the host to
  be added to `EXCAT_EGRESS_ALLOWLIST`.
- **"resolves to a blocked address"**: on-prem tools on private IPs also need
  `EXCAT_SSRF_ALLOW_PRIVATE_NETWORKS=true`. Prefer a proxy or allowlisted gateway.
- **HTTP 401/403 on test**: wrong credentials, or the service account lacks the scope listed in the guide.
- **"… is self-hosted: add '…' to EXCAT_EGRESS_ALLOWLIST"**: the tool has no SaaS domain, so its host must
  be allowlisted.
- **"webhook must be an https URL on …"**: use the Slack incoming-webhook URL or the Teams **Workflows** URL.
  Legacy Office 365 connector URLs are retired.
- **A source shows "Not Integrated" after a pull**: that integration's lookup failed. See the pull summary or
  the *Last error* column. A failed lookup is never reported as *No*.

## Learn more

See the [Integrations guide](../integrations/index.md).

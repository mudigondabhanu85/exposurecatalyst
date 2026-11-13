---
id: settings-integrations
title: Settings — Integrations
page: /settings/integrations
permission: integration:manage
summary: Connect Qualys, Tanium, Wiz, Zafran, ArmorCode and ServiceNow CMDB so advisories show real affected assets.
keywords: [integrations, connectors, qualys, tanium, wiz, zafran, armorcode, servicenow, cmdb, field mapping, test]
docs: integrations/
---

## What this page is for

Integrations answer the question "which of our assets does this CVE affect?". When an analyst clicks
**Check now** on a CVE or **Pull from integrations** on an advisory, every *enabled* integration is queried.
The results fill the asset validation matrix and the Excel attachment.

## How to use it

1. Under **Add a connector**, click **Set up** on a tool. The setup guide on the left lists the prerequisites.
2. Enter a **Name** and the tool's **Base URL**. It must be the vendor's cloud domain, or a host your admin
   added to `EXCAT_EGRESS_ALLOWLIST` for on-prem deployments.
3. Enter the credentials of a dedicated, read-only service account.
4. Click **Save & test**. A green ✓ means authentication and one read-only call succeeded.
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
`advisory:create` can **Pull from integrations**. Every change and test is audited, and credentials never
appear in the audit log.

## Common errors

- **"Base URL rejected: host … is not a known … domain"**: use the vendor's cloud URL, or ask for the host to
  be added to `EXCAT_EGRESS_ALLOWLIST`.
- **"resolves to a blocked address"**: on-prem tools on private IPs also need
  `EXCAT_SSRF_ALLOW_PRIVATE_NETWORKS=true`. Prefer a proxy or allowlisted gateway.
- **HTTP 401/403 on test**: wrong credentials, or the service account lacks the scope listed in the guide.
- **A source shows "Not Integrated" after a pull**: that integration's lookup failed. See the pull summary or
  the *Last error* column. A failed lookup is never reported as *No*.

## Learn more

See the [Integrations guide](../integrations/index.md).

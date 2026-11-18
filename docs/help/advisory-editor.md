---
id: advisory-editor
title: Editing an advisory
page: /advisories/:id
permission: cve:view
summary: Edit the message, recipients and affected assets, then review, approve and deliver.
keywords: [editor, recipients, distribution list, matrix, validated, assets, upload, csv, xlsx, copy for outlook, eml, smtp]
docs: user-guide/advisories/#editing-an-advisory
---

## What this page is for

This is where you build one advisory. The left side holds the message and the affected-asset data, and the
right side shows a live preview of the exact email.

## How to use it

1. **Message.** Edit the subject, title, summary, business impact, remediation, workaround, owner, SLA date,
   vulnerability type (prefilled from the CVE's CWE) and the **Risk owner (BISO)** and **Support team** actions
   (one per line; lines starting with `- ` become bullets), then click **Save**. **Regenerate** rebuilds the subject from the template, for example after you add
   assets: `[CRITICAL] EXCAT-2026-0042 Security Advisory: CVE-… – Product – N assets affected`.
2. **Recipients.** Enter To, CC and BCC addresses separated by commas. Click a **distribution list** to add its
   members, or **Save current recipients as a list** to reuse them later.
3. **Asset validation matrix.** A new advisory lists your **enabled integrations** only (plus any tools an
   admin added in `EXCAT_ADVISORY_SOURCES`). Choose which tools the email covers:
   - Untick **In email** to leave a tool out of the email, the Excel file and the totals (its assets too).
   - **Add tool** adds any other tool you checked by hand, such as Tanium.
   - Set **Check available** (does the tool have a detection for this CVE?) and the **Detection method**
     (vulnerability check, software inventory, asset inventory / CMDB, manual analysis).
   - The note under each tool is printed in the email's *Notes*. Leave it empty to use the generated sentence,
     for example "Checks are available in Qualys; however, no vulnerable instances were identified."

   Click **Pull from integrations** to query every enabled tool. This replaces integration rows, keeps your
   manual rows and your choices, and marks each successfully checked source *Yes* or *No*. Type a **Manual
   count** when you checked a tool by hand. Enter `0` to record that you checked and found nothing (*No*).
4. **Affected assets.** Add rows one at a time, or **Upload CSV/XLSX** with a header row. Recognized columns
   include Hostname, IP Address, OS, Cloud Account, Resource ID, Owner, Business Unit, Environment, Support
   Group (or Assignment Group), Asset Class, Detection Method, Detection Date, Source and QID/Plugin/ID. Rows without a Source column use the source you pick.
5. **Submit for review.** The advisory locks until an approver approves it or asks for changes. A reviewer's
   comment appears at the top.
6. **Deliver**, once the advisory is approved:
   - **Send via SMTP…** shows a confirmation with every recipient before sending.
   - **Copy for Outlook** puts rich HTML on the clipboard. Paste it into a new Outlook message and attach the
     Excel file.
   - **Download .eml** opens in Outlook as an editable draft (`X-Unsent: 1`), with the Excel file attached.
   - **Excel**, **HTML** and **PDF** download those formats.

### Tickets & sharing

When Jira, ServiceNow ITSM, Slack or Teams integrations are enabled, an approved (or sent) advisory shows
**Tickets & sharing**. Users with `advisory:send` can create a ticket (summary, severity-based priority,
affected-asset count, remediation and a link back to the advisory) or post the advisory to a channel. Each
attempt is listed with its ticket number or error, and is recorded in the audit trail.

## Fields and columns

| Field | Meaning |
|---|---|
| Validated = **Yes** | Affected assets were actually found for this source |
| Validated = **No** | The source was checked (integrated, or a manual count of 0) and found nothing |
| **Not Integrated** | No connector and no manual entry for this source |
| **Check available** | Whether the tool has a check for this CVE. *Yes* with 0 assets = "checks available, no vulnerable instances" |
| **Detection method** | How the tool found assets. Software or asset inventory matches are described as *potentially* vulnerable |
| **In email** | Unticked tools (and their assets) are left out of the email, the Excel file and the totals |
| **Manual** | The count or rows were entered or uploaded by an analyst. This label also appears in the email and Excel |
| Total unique affected assets | Rows de-duplicated across sources by hostname, IP address and cloud resource ID |

## Required permissions

Editing needs `advisory:create`. Approving needs `advisory:approve`, and you can't approve your own advisory.
Sending needs `advisory:send`. Copy and downloads need `advisory:export`.

## Common errors

- **"Provide a hostname, IP address or resource ID"**: each asset needs at least one identifier.
- **"no recognised columns"** on upload: add a header row, for example `Hostname,IP Address,Source`.
- **"SMTP is not configured"**: ask an admin to set up **Settings → SMTP**, or use **Download .eml** instead.
- **Copy for Outlook does nothing**: your browser blocked clipboard access. Allow it for this site, or use .eml.

## Learn more

See the [Advisories user guide](../user-guide/advisories.md).

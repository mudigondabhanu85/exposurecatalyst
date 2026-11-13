---
id: advisories
title: Advisory Email Generator
page: /advisories
permission: cve:view
summary: Turn a CVE and its affected assets into a reviewed, branded advisory email with a unique EXCAT ID.
keywords: [advisory, email, outlook, eml, excel, approval, workflow, send]
docs: user-guide/advisories/
---

## What this page is for

The Advisory Email Generator turns a CVE and the assets it affects into a professional advisory for
stakeholders. Each advisory gets a unique ID (`EXCAT-YYYY-NNNN`) to quote in tickets and replies. Every
advisory goes through **draft → review → approved** before anyone can send or export it.

## How to use it

1. Open a CVE in **CVE Intelligence** and click **Create Advisory Email**. A draft is created and pre-filled
   from the CVE: severity, scores, KEV status, affected products, remediation and the SLA due date.
2. Add recipients, edit the text and record affected assets. The preview on the right shows exactly what
   recipients will see.
3. Click **Submit for review**. An approver, who must be someone other than the author, approves it or
   requests changes.
4. Once it's approved, deliver it: **Send via SMTP**, **Copy for Outlook**, **Download .eml**, or download it
   as HTML, PDF or Excel.
5. Use the **Status** filter to find drafts waiting for you, or advisories already sent.

## Fields and columns

| Column | Meaning | Example |
|---|---|---|
| Advisory ID | Unique, sequential per year | `EXCAT-2026-0042` |
| Status | `draft`, `in review`, `approved`, `sent`, `cancelled` | `approved` |
| Severity | Taken from the CVE (KEV-listed CVEs without a score default to High) | `CRITICAL` |
| Author | Who created the draft | `ana` |

## Required permissions

| Action | Permission | Default roles |
|---|---|---|
| Create and edit drafts, submit, add assets | `advisory:create` | Security Analyst |
| Approve or request changes | `advisory:approve` | Approver |
| Send via SMTP | `advisory:send` | Security Analyst |
| Copy, .eml, HTML, PDF, Excel | `advisory:export` | Security Analyst, Approver |
| Edit templates | `template:manage` | Admin |

## Common errors

- **"Add at least one To recipient"**: an advisory can't be submitted without a To address.
- **"advisory is 'draft'; this action needs: approved, sent"**: exports and sending unlock only after approval.
- **"segregation of duties"**: you can't approve your own advisory. Ask another approver.

## Learn more

See the [Advisories user guide](../user-guide/advisories.md).

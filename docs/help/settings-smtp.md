---
id: settings-smtp
title: Settings — SMTP
page: /settings/smtp
permission: settings:manage
summary: Choose how advisories and alerts are emailed (SMTP relay, Microsoft 365 OAuth2 or Amazon SES API) and send a test.
keywords: [smtp, email, office 365, microsoft 365, oauth2, xoauth2, entra, ses, amazon ses, iam role, starttls, relay, test]
docs: admin-guide/smtp/
---

## What this page is for

Configures how ExposureCatalyst sends advisory and alert emails. There are three delivery methods:

| Method | When to use it |
|---|---|
| **Microsoft 365 — OAuth2** | Exchange Online. An Entra ID app sends as a dedicated mailbox, and no mailbox password is stored |
| **Amazon SES — API** | AWS deployments. Uses the task's IAM role, so no keys are stored |
| **SMTP relay — username & password** | Corporate relays, the SES SMTP interface, or other providers |

## How to use it

1. Choose a **Delivery method**, or pick a **preset** (Microsoft 365, Microsoft 365 GCC High, Amazon SES API,
   Amazon SES SMTP, Corporate relay) to fill in the host, port and security.
2. Fill in the method's fields:
    - **Microsoft 365 — OAuth2**: the sending mailbox, Directory (tenant) ID, Application (client) ID and client
      secret. The app needs `SMTP.SendAsApp` and access to the mailbox. The
      [admin guide](../admin-guide/smtp.md#microsoft-365-oauth2) has the exact steps.
    - **Amazon SES — API**: the region (e.g. `us-east-1`) and an optional configuration set. The From address
      must be on a verified SES identity.
    - **SMTP relay**: host, port, security, and a username and password if the relay needs them.
3. Set **From address**, **From name** and an optional **Reply-To**.
4. Click **Save**, then **Send test** to a mailbox you can check.

Secrets (password, client secret) are encrypted and never shown again. Leave them blank to keep the stored
value.

## Fields and columns

| Field | Notes |
|---|---|
| Security | STARTTLS and SSL/TLS verify the server certificate. *None* is offered only for password relays, and is refused unless `EXCAT_SMTP_ALLOW_PLAINTEXT=true` (dev only) |
| Port | Must be in `EXCAT_SMTP_ALLOWED_PORTS` (default 25, 465, 587, 2525) |
| Cloud (Microsoft 365) | *GCC High / DoD* uses `login.microsoftonline.us` and `smtp.office365.us` |
| Configuration set (SES) | Optional SES configuration set for bounce, complaint and delivery events |

## Required permissions

`settings:manage` (Admin, Super Admin). Every change and test is written to the audit log; secrets never
are.

## Common errors

- **"Entra ID did not return an access token"**: wrong tenant, client ID or secret, or the secret expired.
- **`SMTPAuthenticationError` with OAuth2**: admin consent for `SMTP.SendAsApp`, the Exchange service
  principal, mailbox access, or SMTP AUTH on the mailbox is missing.
- **SES "Email address is not verified"**: verify the From identity. In the SES sandbox, recipients must be
  verified too.
- **SES `AccessDenied`**: the task role lacks `ses:SendEmail` on the identity (Terraform `ses_identity_arns`).
- **"SMTP host is on a private network"**: internal relays need `EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true`.

## Learn more

See the [SMTP admin guide](../admin-guide/smtp.md).

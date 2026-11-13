---
id: settings-smtp
title: Settings — SMTP
page: /settings/smtp
permission: settings:manage
summary: Configure the outbound mail relay used to send advisories, and send a test email.
keywords: [smtp, email, office 365, microsoft 365, ses, starttls, relay, test]
docs: admin-guide/smtp/
---

## What this page is for

Configures how ExposureCatalyst sends advisory emails. Any SMTP relay works, including Microsoft 365,
Amazon SES and a corporate relay. The password is encrypted at rest and is never shown again.

## How to use it

1. Enter **Host**, **Port** and **Security**:

    | Provider | Host | Port / security |
    |---|---|---|
    | Microsoft 365 (SMTP AUTH) | `smtp.office365.com` | 587 / STARTTLS |
    | Amazon SES | `email-smtp.<region>.amazonaws.com` | 587 / STARTTLS (SES SMTP credentials) |
    | Corporate relay | your relay | 25 or 587 / STARTTLS |

2. Enter **Username** and **Password** if the relay requires authentication. Leave the password blank later
   to keep the stored one.
3. Set **From address** (it must be allowed to send on your relay), **From name** and an optional
   **Reply-To**.
4. Click **Save**, then **Send test** to a mailbox you can check.

## Fields and columns

| Field | Notes |
|---|---|
| Security | STARTTLS and SSL/TLS verify the server certificate. *None* is refused unless `EXCAT_SMTP_ALLOW_PLAINTEXT=true` (dev only) |
| Port | Must be in `EXCAT_SMTP_ALLOWED_PORTS` (default 25, 465, 587, 2525) |

## Required permissions

`settings:manage` (Admin, Super Admin). Every change and test is written to the audit log.

## Common errors

- **"SMTP host is on a private network"**: internal relays are blocked by default to prevent SSRF. Set
  `EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true` if your relay is internal.
- **`SMTPAuthenticationError`**: wrong credentials, or SMTP AUTH is disabled for the mailbox (Microsoft 365).
- **`SMTPRecipientsRefused` / `SMTPSenderRefused`**: the relay doesn't allow this From address.
- **`SSLCertVerificationError`**: the relay's certificate isn't trusted. Fix the certificate rather than
  disabling TLS.

## Learn more

See the [SMTP admin guide](../admin-guide/smtp.md).

# SMTP & email delivery

Advisories are sent through an SMTP relay configured in **Settings → SMTP** (`settings:manage`).

## Providers

| Provider | Host | Port / security | Notes |
|---|---|---|---|
| Microsoft 365 | `smtp.office365.com` | 587 / STARTTLS | SMTP AUTH must be enabled for the sending mailbox. OAuth2 (XOAUTH2) is planned. Until then, use a dedicated service mailbox |
| Amazon SES | `email-smtp.<region>.amazonaws.com` | 587 / STARTTLS | Use SES **SMTP credentials** (not IAM keys) and a verified From identity. Configure SPF, DKIM and DMARC |
| Corporate relay | internal host | 25 or 587 / STARTTLS | Requires `EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true` |

## Security controls

- The password is **Fernet-encrypted** at rest (`EXCAT_ENCRYPTION_KEY`). It's never returned by the API or
  logged. Leave the field blank to keep it.
- **TLS**: STARTTLS and SSL/TLS use certificate and hostname verification. Plaintext is refused unless
  `EXCAT_SMTP_ALLOW_PLAINTEXT=true`, which is rejected in production.
- **SSRF guard**: the relay host is resolved and checked. Cloud metadata addresses are always blocked,
  private ranges are blocked unless explicitly allowed, and the port must be in `EXCAT_SMTP_ALLOWED_PORTS`.
- **Header injection**: subjects and names are stripped of CR/LF and control characters.
- **BCC privacy**: BCC recipients appear only in the SMTP envelope, never in the sent headers.
- In AWS, add the relay host to the Network Firewall allowlist, or use SES through a VPC endpoint.

## Testing

Use **Send test** after saving. For local development, run a catch-all SMTP server such as Mailpit:

```bash
docker run -d --name mailpit -p 127.0.0.1:1025:1025 -p 127.0.0.1:8025:8025 axllent/mailpit
# .env (dev only)
EXCAT_SMTP_ALLOWED_PORTS=25,465,587,1025
EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true
EXCAT_SMTP_ALLOW_PLAINTEXT=true
```

Then configure host `localhost` (or `mailpit` inside compose), port 1025, security *None*, and open
`http://localhost:8025` to see the message.

## Troubleshooting

| Error | Fix |
|---|---|
| `SMTPAuthenticationError` | Check the credentials. For M365, enable SMTP AUTH on the mailbox |
| `SMTPSenderRefused` | The From address isn't allowed on the relay or not verified in SES |
| `SSLCertVerificationError` | The relay's certificate chain isn't trusted. Fix the certificate; don't disable TLS |
| `SMTP host is on a private network` | Set `EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true` for internal relays |
| Send fails with 502 | The advisory stays *approved*, and the failure is recorded in its audit trail. Fix the relay and send again |

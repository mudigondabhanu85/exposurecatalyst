# SMTP & email delivery

Advisories and email alerts are sent with the delivery method configured in **Settings → SMTP**
(`settings:manage`). Pick a method, or start from a **preset**, then **Save** and **Send test**.

| Method | Use it for | Credentials stored in ExposureCatalyst |
|---|---|---|
| **Microsoft 365 — OAuth2** | Exchange Online (basic SMTP AUTH is being retired) | Entra ID client secret (encrypted) |
| **Amazon SES — API** | AWS deployments | None: uses the AWS credential chain (ECS task role) |
| **SMTP relay — username & password** | Corporate relays, Amazon SES SMTP interface, other providers | SMTP password (encrypted) |

## Microsoft 365 — OAuth2

ExposureCatalyst authenticates to `smtp.office365.com:587` with SMTP AUTH **XOAUTH2**, using an app-only
token from Entra ID (OAuth2 client credentials, scope `https://outlook.office365.com/.default`). No user
password is stored, and the app can only send as the mailboxes you grant it.

### 1. Register the app (Entra admin center)

1. **App registrations → New registration**, e.g. *ExposureCatalyst mail*, single tenant. Note the
   **Application (client) ID** and **Directory (tenant) ID**.
2. **API permissions → Add a permission → APIs my organization uses → Office 365 Exchange Online →
   Application permissions → `SMTP.SendAsApp`**, then **Grant admin consent**.
3. **Certificates & secrets → New client secret**. Copy the value (it is shown once) and note its expiry.

### 2. Allow the app to send as the mailbox (Exchange Online PowerShell)

```powershell
Connect-ExchangeOnline
# ObjectId = the *Enterprise application* (service principal) object ID, not the app registration's
New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "ExposureCatalyst mail"
Add-MailboxPermission -Identity "secops@contoso.com" -User <enterprise-app-object-id> -AccessRights FullAccess
# SMTP AUTH must be enabled for the sending mailbox (OAuth still uses the SMTP AUTH protocol)
Set-CASMailbox -Identity "secops@contoso.com" -SmtpClientAuthenticationDisabled $false
```

Grant only the dedicated sending mailbox, never `FullAccess` on other mailboxes. If SMTP AUTH is disabled
organisation-wide (`Get-TransportConfig | fl SmtpClientAuthenticationDisabled`), the per-mailbox setting
above overrides it for that mailbox only.

### 3. Configure ExposureCatalyst

Settings → SMTP → **Microsoft 365 — OAuth2** (or the *Microsoft 365 (OAuth2)* preset):

| Field | Value |
|---|---|
| Host / Port / Security | `smtp.office365.com` / 587 / STARTTLS (GCC High / DoD: `smtp.office365.us`, cloud *GCC High / DoD*) |
| Sending mailbox | `secops@contoso.com` (the mailbox granted above) |
| From address | the same mailbox, or an address it has *Send As* on |
| Directory (tenant) ID / Application (client) ID / Client secret | from step 1 |

Tokens are cached in memory until shortly before they expire. Rotate the client secret before its expiry:
paste the new value and save (leave it blank to keep the stored one).

## Amazon SES — API (IAM role)

ExposureCatalyst calls **SESv2 `SendEmail`** with the complete MIME message (logo, Excel attachment and
headers unchanged), in batches of 50 recipients. Credentials come from the AWS default chain, which is the
ECS task role in the reference deployment, so no keys are stored.

1. **Verify an identity** in SES (a domain is better than an address). Publish the DKIM CNAMEs, set a custom
   MAIL FROM domain for SPF alignment, and publish a DMARC record.
2. **Request production access** if the account is still in the SES sandbox. In the sandbox, every
   recipient must be verified too.
3. **Grant send permission.** With the Terraform reference deployment, set
   `ses_identity_arns = ["arn:aws:ses:<region>:<account>:identity/example.com"]`. This gives the API and
   scheduler task roles `ses:SendEmail` / `ses:SendRawEmail` on those identities and opens
   `email.<region>.amazonaws.com` in the Network Firewall. Elsewhere, grant the same actions to whatever
   identity the app runs as.
4. Optional: create a **configuration set** with event destinations (bounces, complaints, deliveries).
5. Settings → SMTP → **Amazon SES — API**. Enter the region (e.g. `us-east-1`), optional configuration set,
   and a From address on the verified identity.

The container image includes boto3. For a pip install outside Docker, use `pip install "exposurecatalyst[aws]"`.

### SES SMTP interface (alternative)

Without an IAM role (for example on-prem), use **SMTP relay** with host
`email-smtp.<region>.amazonaws.com`, port 587 / STARTTLS and SES **SMTP credentials**. These are generated
in the SES console and are not the same as IAM access keys.

## SMTP relay — username & password

| Provider | Host | Port / security | Notes |
|---|---|---|---|
| Corporate relay | internal host | 25 or 587 / STARTTLS | Requires `EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true` |
| Amazon SES (SMTP) | `email-smtp.<region>.amazonaws.com` | 587 / STARTTLS | SES SMTP credentials |
| Microsoft 365 (basic auth) | `smtp.office365.com` | 587 / STARTTLS | Only while your tenant still allows basic SMTP AUTH. Prefer OAuth2 |

## Network egress (AWS reference deployment)

The Network Firewall matches HTTPS by TLS SNI. **SMTP on 587 starts in plaintext (STARTTLS), so it carries
no SNI and cannot be matched by domain.** Choose one:

- **SES API (recommended):** set `ses_identity_arns`. The HTTPS endpoint is allowlisted automatically.
- **SMTP relay or Microsoft 365:** set `smtp_egress_cidrs` to the relay's addresses. For Microsoft 365, use
  the Exchange Online SMTP ranges from `https://endpoints.office.com`, and keep them current.
  `login.microsoftonline.com` (the token endpoint) is in the default HTTPS allowlist.

## Security controls

- The SMTP password and Entra ID client secret are **Fernet-encrypted** at rest (`EXCAT_ENCRYPTION_KEY`).
  They're never returned by the API or written to logs or audit records. Audit entries record only that a
  secret changed.
- **TLS**: STARTTLS and SSL/TLS verify the certificate and hostname. OAuth2 refuses plaintext. Plaintext is
  refused unless `EXCAT_SMTP_ALLOW_PLAINTEXT=true`, which is rejected in production.
- **SSRF guard**: the relay host is resolved and checked. Cloud metadata addresses are always blocked,
  private ranges are blocked unless explicitly allowed, and the port must be in `EXCAT_SMTP_ALLOWED_PORTS`.
  The Entra ID token request goes only to `login.microsoftonline.com` / `.us`. The SES region is validated
  against the AWS region format.
- **Header injection**: subjects and names are stripped of CR/LF and control characters.
- **BCC privacy**: BCC recipients appear only in the envelope (SMTP `RCPT TO`, or the SES destination
  list), never in the sent headers.

## Testing

Use **Send test** after saving. It uses the saved method and reports the message ID. For local
development, run a catch-all SMTP server such as Mailpit:

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
| `Entra ID did not return an access token` | Wrong tenant, client ID or secret (or the secret expired) |
| `SMTPAuthenticationError` with OAuth2 (`535 5.7.3`) | Missing `SMTP.SendAsApp` consent, service principal not registered in Exchange, no `FullAccess` on the mailbox, or SMTP AUTH disabled for it |
| `SMTPAuthenticationError` with a password | Check the credentials. For M365, basic SMTP AUTH may be disabled; switch to OAuth2 |
| `MessageRejected: Email address is not verified` (SES) | Verify the From identity. In the sandbox, verify recipients or request production access |
| `AccessDenied ... ses:SendEmail` (SES) | Add the identity ARN to `ses_identity_arns`, or grant the role `ses:SendEmail`/`SendRawEmail` |
| `Amazon SES API needs boto3` | Install the `aws` extra (`pip install "exposurecatalyst[aws]"`). The container image includes it |
| `SMTPSenderRefused` | The From address isn't allowed on the relay or not verified in SES |
| `SSLCertVerificationError` | The relay's certificate chain isn't trusted. Fix the certificate; don't disable TLS |
| `SMTP host is on a private network` | Set `EXCAT_SMTP_ALLOW_PRIVATE_HOSTS=true` for internal relays |
| Timeouts from AWS | SMTP 587 needs `smtp_egress_cidrs`; the SES API needs `ses_identity_arns` |
| Send fails with 502 | The advisory stays *approved*, and the failure is recorded in its audit trail. Fix the configuration and send again |

---
id: settings-certificates
title: Settings — Certificates & Domain
page: /settings/certificates
permission: settings:manage
summary: See the TLS certificate the built-in proxy serves and every URL derived from the domain; install a certificate, generate a CSR, roll back, trust internal CAs or use ACME.
keywords: [certificate, tls, ssl, https, csr, pfx, pkcs12, pem, rollback, acme, lets encrypt, domain, fqdn, saml, okta, ca bundle, self-signed, expiry]
docs: getting-started/installation/
---

## What this page is for

The Docker deployment serves the app over HTTPS through a built-in proxy. This page shows the certificate it
serves, the domain (FQDN), and every URL derived from it: the SAML entity ID, ACS URL and SP metadata, the OIDC
redirect URI and email links. Each URL has a copy button for your identity provider.

Installing certificates, generating CSRs, rolling back and the trusted CA bundle need the
`features.ui_tls_management` flag. ACME also needs `features.acme`. Without them, the page is read-only.

## How to use it

**Install a certificate signed by your CA**

1. Under **Install a certificate**, choose **PEM files** (certificate, key and chain, or a single bundle),
   **PKCS#12 / PFX** (with its password), or **Paste PEM**.
2. Click **Validate** to check it without changing anything. The checks are: the key matches the certificate,
   it is not expired or not-yet-valid, the chain builds to a trusted root, the SANs cover the FQDN, the key is
   strong enough (RSA ≥ 2048, ECDSA P-256+), and no SHA-1 or MD5 signatures are used.
3. Click **Validate & activate**. The proxy reloads without dropping connections, and the app confirms the new
   certificate is being served. If anything fails, the previous certificate is restored automatically.

**Generate a CSR (the key never leaves the server)**

1. Under **Generate a CSR**, check the common name (pre-filled with the FQDN), add SANs and choose a key type.
2. Download the CSR and have your CA sign it.
3. Under the pending request, upload the signed certificate (plus the chain if your CA provides one).

**Roll back**: **Roll back to previous** re-activates the certificate that was active before the last change.

**Trusted CA bundle**: upload your internal root or issuing CAs, or a TLS-inspection proxy's CA. Outbound
connections (CVE sources, integrations, AI providers, SMTP) then trust them in addition to the public roots.
They are also used to validate uploaded certificates.

## Fields and columns

| Item | Meaning |
|---|---|
| Source | *Self-signed (generated)* until you install a certificate; *uploaded*; or ACME |
| Matches domain | Whether the certificate's SANs cover the configured FQDN |
| History | Every certificate installed: *active*, *previous* (rollback target), *archived*, *failed* |
| Expiry alerts | Admins with an email address are emailed at 30, 14, 7 and 1 days before expiry (needs SMTP) |

## Required permissions

`settings:manage` (Admin, Super Admin). Every install, rollback, CSR, trusted-CA change and ACME change is
written to the audit log. Private keys are never displayed or exported, and are encrypted at rest.

## Common errors

- **"the chain does not build to a trusted root"**: include the intermediate certificate(s), or upload your
  internal root under **Trusted CA bundle**.
- **"the SANs … do not cover …"**: the certificate is for another name. Reissue it with the FQDN as a SAN.
- **"the private key does not match"**: the key belongs to a different certificate or CSR.
- **"activation failed, previous certificate restored"**: the proxy did not serve the new certificate. Check
  `./run.sh logs proxy`.

## Learn more

See the TLS certificates and Map your domain guides in the documentation.

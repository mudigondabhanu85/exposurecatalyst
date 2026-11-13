# Okta SAML single sign-on

ExposureCatalyst is a SAML 2.0 service provider (SP). The in-app wizard (**Settings → Identity & SSO**,
`sso:manage`) walks through the steps below, and each step shows ✓ when complete.

## Prerequisites

- Okta admin rights to create an app integration.
- Okta groups (or SailPoint-managed groups pushed to Okta) for each ExposureCatalyst role, for example
  `ExcatViewers`, `ExcatAnalysts`, `ExcatApprovers`, `ExcatAdmins`.
- `EXCAT_PUBLIC_URL` set to the exact external HTTPS URL users browse to. The ACS and Entity ID are derived
  from it.
- A local break-glass account with TOTP, so you can recover if SSO is misconfigured.

## 1. Create the app in Okta

Okta Admin → **Applications → Create App Integration → SAML 2.0**.

| Okta field | Value |
|---|---|
| App name | ExposureCatalyst |
| **App logo** | `brand/assets/png/app-icon-512.png`. Download it from the wizard (*App tile logo*) |
| Single sign-on URL | `https://<your-host>/api/auth/saml/acs` (tick *Use this for Recipient URL and Destination URL*) |
| Audience URI (SP Entity ID) | `https://<your-host>/api/saml/metadata` |
| Name ID format / Application username | EmailAddress / Email |
| Response / Assertion signature | Signed / Signed, **RSA-SHA256** |
| Attribute statements | `email` → user.email, `firstName` → user.firstName, `lastName` → user.lastName |
| Group attribute statement | `groups`, filter *Starts with* `Excat` (send only relevant groups) |

The wizard's *SP metadata XML* download contains the same values and the SP signing certificate. Okta can
validate signed AuthnRequests with it (*Signature Certificate* in advanced settings).

Assign the Excat groups to the app. In the app's sign-on policy, **require MFA**: ExposureCatalyst treats SSO
sessions as MFA-verified.

## 2. Import IdP metadata

Copy the **Metadata URL** from the app's *Sign On* tab and click **Import from URL**. The fetch is restricted
to Okta domains (`*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com`, `*.okta-gov.com`) or
`EXCAT_EGRESS_ALLOWLIST`. Alternatively, paste the XML. This stores the IdP entity ID, SSO URL and signing
certificate.

## 3. Attributes and provisioning

The defaults match the statements above. **JIT provisioning** creates the user on first sign-in. Turn it off
if SailPoint provisions accounts via [SCIM](sailpoint.md). **IdP-initiated sign-in** (from the Okta dashboard
tile) is off by default because unsolicited responses can't be bound to a request. Enable it only if you need
the dashboard tile to sign users straight in.

## 4. Map groups to roles

Add a mapping per group, for example `ExcatAnalysts → Security Analyst`. See the
[RBAC guide](rbac.md#sailpoint-okta-group-mapping). SAML can't be enabled until at least one mapping exists.

## 5. Enable and test

Click **Enable SAML sign-in**, then **Test sign-in in a new tab**, keeping your admin session open. The login
page then shows **Sign in with Okta**.

## Troubleshooting

| Message on the login page | Cause and fix |
|---|---|
| `unknown, expired or already-used AuthnRequest` | Sign-in took over 10 minutes, the browser was reused, or the Okta tile was used with IdP-initiated sign-in disabled. Start again from the login page |
| `IdP-initiated sign-in is disabled` | The user clicked the Okta dashboard tile. Enable IdP-initiated sign-in, or set the tile to open `https://<host>/api/auth/saml/login` |
| `SAML validation failed: … Signature validation failed` | The certificate changed in Okta (rotation). Re-import metadata |
| `… audience` / `… Destination` / `… Recipient` | The Okta app's ACS or Entity ID doesn't match `EXCAT_PUBLIC_URL` |
| `invalid_response … SHA1` | Set Okta signature and digest algorithms to SHA-256 |
| `your groups are not mapped to any ExposureCatalyst role` | Add a mapping, or assign the user to a mapped group |
| `identity matches a local (break-glass) account` | Local accounts can't be used via SSO. Use a different email for the local account |

Every SSO success and failure is in the audit log (`auth.login`, `method: saml`, with the reason).

# Okta OpenID Connect (OIDC) sign-in

OIDC is the alternative to [SAML](okta-saml.md). Use whichever your identity team prefers; both can be enabled at
the same time. Both use the same **group → role mappings**, the same just-in-time (JIT) provisioning rules and
the same protection of local break-glass accounts. Configure it in **Settings → Identity & SSO → Alternative:
OpenID Connect** (`sso:manage`).

## How it works

ExposureCatalyst is a confidential OIDC client using the **Authorization Code flow with PKCE (S256)**:

1. **Sign in with Okta** calls `/api/auth/oidc/login`. The server creates a random `state`, `nonce` and PKCE
   verifier. The state is stored hashed and the verifier encrypted, single use, valid 10 minutes. Then it
   redirects the browser to Okta.
2. The user authenticates at Okta (MFA is enforced by your Okta sign-on policy).
3. Okta redirects to `/api/auth/oidc/callback?code=…&state=…`.
4. The server exchanges the code at the token endpoint with the client secret and the PKCE verifier, then
   validates the **ID token**: signature against Okta's JWKS (asymmetric algorithms only), `iss`, `aud`
   (and `azp` when there are several audiences), `exp`/`iat` (60 s leeway) and `nonce`.
5. Email comes from the `email` claim (refused if `email_verified` is false). Groups come from the `groups`
   claim, or from the userinfo endpoint if the ID token doesn't carry them.
6. Groups map to roles. No mapped role means no access, and an OIDC identity can never sign in as a local
   account.

All provider endpoints come from the issuer's discovery document and must be **https on the issuer's host**.
The host must be an Okta domain or listed in `EXCAT_EGRESS_ALLOWLIST` (and the Network Firewall allowlist).

## 1. Create the app in Okta

Okta Admin → **Applications → Create App Integration → OIDC – OpenID Connect → Web Application**.

| Okta field | Value |
|---|---|
| App integration name | ExposureCatalyst |
| **Logo** | `brand/assets/png/app-icon-512.png` (download it from the SAML wizard's *App tile logo*) |
| Grant type | **Authorization Code** only (no Implicit, no Refresh Token needed) |
| Sign-in redirect URI | `https://<your-host>/api/auth/oidc/callback` (copy it from the settings page) |
| Sign-out redirect URI | none |
| Client authentication | Client secret, **Require PKCE** ticked |
| Assignments | The `Excat*` groups |

Then add a groups claim. The approach depends on the authorization server:

- **Org authorization server** (issuer `https://<org>.okta.com`): app → **Sign On → OpenID Connect ID Token →
  Groups claim type: Filter**, name `groups`, *Starts with* `Excat`.
- **Custom authorization server** (issuer `https://<org>.okta.com/oauth2/default`): Security → API →
  Authorization Servers → *default* → **Claims → Add Claim**: name `groups`, include in **ID Token**, value
  type *Groups*, filter *Starts with* `Excat`.

## 2. Configure ExposureCatalyst

| Field | Value |
|---|---|
| Issuer URL | `https://<org>.okta.com` or `https://<org>.okta.com/oauth2/default`, exactly as in the token's `iss` |
| Client ID / secret | From the Okta app's *General* tab. The secret is write-only and encrypted at rest |
| Client authentication | *HTTP Basic* (Okta's default) |
| Scopes | `openid email profile groups` |
| Claims | `email`, `given_name`, `family_name`, `groups` |
| JIT provisioning | On, unless SailPoint provisions users through SCIM |

Click **Test discovery**: it loads the discovery document and signing keys and shows the token endpoint.
Then make sure at least one group mapping exists (Step 4), click **Enable OIDC sign-in**, and use **Test sign-in
in a new tab** while you keep the admin session open.

## Troubleshooting

| Message on the login page | Fix |
|---|---|
| *identity provider returned access_denied: User is not assigned…* | Assign the user (or their group) to the Okta app |
| *sign-in request is unknown, expired or already used* | The sign-in took longer than 10 minutes, or the browser replayed the callback. Start again |
| *token exchange failed: …HTTP 401* | Wrong client secret or client authentication method |
| *token exchange failed: …HTTP 400* | Redirect URI in Okta doesn't exactly match the one shown in settings (check `EXCAT_PUBLIC_URL`) |
| *ID token rejected: … 'iss'* | The issuer URL doesn't match the token. Use the org issuer or the `/oauth2/<id>` issuer consistently |
| *ID token has no 'email' claim* | Add the `email` scope |
| *your groups are not mapped to any ExposureCatalyst role* | Add the groups claim (step 1) and a mapping. The sign-in attempt lists unmapped groups on the settings page |
| *Identity provider unavailable* | Check egress to the Okta domain (firewall, proxy) |

## Rotating the client secret

Okta lets an app have two active secrets. Create a new one in Okta, paste it into ExposureCatalyst and save,
test a sign-in, then deactivate the old secret in Okta. Okta's signing keys rotate automatically:
ExposureCatalyst refetches the JWKS when a token uses an unknown key ID.

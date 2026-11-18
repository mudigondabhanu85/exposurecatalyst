# Map your domain

ExposureCatalyst serves one hostname (the **FQDN**, e.g. `exposurecatalyst.company.com`). Everything that
depends on the public URL follows it: the proxy, SAML entity ID, ACS URL and SP metadata, the OIDC redirect
URI, links in advisory emails, allowed Host headers, CSRF origins, Open Graph URLs and the self-signed
certificate's SAN.

When `fqdn` is not set outside Docker, nothing changes: `EXCAT_PUBLIC_URL` is used exactly as before. The
Docker deployment defaults `fqdn` to `localhost`.

## 1. DNS

Create a record pointing at the Docker host:

| Type | Name | Value |
|---|---|---|
| A / AAAA | `exposurecatalyst.company.com` | the host's IP address |
| or CNAME | `exposurecatalyst.company.com` | the host's existing DNS name (or your load balancer) |

Check: `./run.sh doctor` reports whether the name resolves.

## 2. Firewall

Allow inbound **TCP 443** (and **80**, which only redirects to HTTPS — and is needed for ACME HTTP-01) from
your users' networks. Nothing else is published. Behind a load balancer, set `trusted_proxies` to its CIDRs.

## 3. Configure and apply

```yaml
# config/exposurecatalyst.yaml
fqdn: exposurecatalyst.company.com
https_port: 443
```

```bash
./run.sh
```

On start the app detects the change and admins see **"Domain changed — update Okta (download new SP
metadata), DNS, and the TLS certificate."** In self-signed mode a new certificate is generated for the new name.

## 4. Certificate

Install a certificate whose SANs cover the FQDN — upload, CSR or ACME
([TLS certificates](tls-certificates.md)). Settings → Certificates & Domain warns while it doesn't match.

## 5. Identity provider

Settings → Certificates & Domain lists every derived URL with a copy button.

- **Okta SAML**: download the new SP metadata (Settings → Identity & SSO) and update the app's Single sign-on
  URL / Audience — or re-import the metadata. An explicitly configured SP entity ID is kept as it is.
- **OIDC**: add the new redirect URI (`https://<fqdn>/api/auth/oidc/callback`) to the app.
- **SCIM**: update the base URL in SailPoint if it pointed at the old name.

Existing sessions keep working; the previous `EXCAT_PUBLIC_URL`, if set, stays accepted as an origin.

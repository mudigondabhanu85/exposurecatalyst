# Threat model (STRIDE)

Scope: the production deployment ([architecture](../architecture/high-level.md), [DFDs](../architecture/data-flow.md)).
Assets, by priority: **integration and AI credentials** (Restricted), **asset inventory and exposure** (Confidential),
**advisory recipients and content** (Confidential), **integrity of advisories and the audit trail**, and the
**availability** of timely CVE intelligence.

Ratings: Likelihood (L) and Impact (I) from 1 (low) to 3 (high). **Residual** is the risk after the listed
controls.

## TB1 — Users ↔ Edge/App

| STRIDE | Threat | Controls | L/I | Residual |
|---|---|---|---|---|
| S | Credential stuffing or phishing of local accounts | SSO-first (Okta MFA). Local break-glass only, with TOTP (replay-protected). Lockout. Per-IP and WAF rate limits. Generic errors | 2/3 | Low |
| S | Session hijack | `__Host-` Secure HttpOnly SameSite=Strict cookie. Server-side hashed tokens. Idle (30 min) and absolute (8 h) timeouts. Revocation on role change | 1/3 | Low |
| T | CSRF / cross-origin state change | Session-bound CSRF token + Origin check on every unsafe method | 1/2 | Low |
| R | User denies sending an advisory | Hash-chained audit (`advisory.sent` with actor, recipients, Message-ID). Delivery records | 1/2 | Low |
| I | XSS exposing data (via CVE or news text) | React escaping. Markdown without raw HTML. Strict CSP (`script-src 'self'`). Upstream links restricted to http(s), `rel=noopener` | 1/3 | Low |
| E | Privilege escalation via RBAC APIs | Server-side `require()` on every route (tested across >80 routes). Can't grant what you don't hold. Can't change your own roles | 1/3 | Low |
| D | Login brute force or API flooding | WAF managed rules + login rate rule. App rate limits. Lockout | 2/2 | Low |

## TB2 — Identity providers ↔ App (SAML, OIDC, SCIM)

| STRIDE | Threat | Controls | L/I | Residual |
|---|---|---|---|---|
| S | Forged or altered SAML assertion | Signed assertions required. Strict mode. SHA-1 rejected. Audience/Recipient/Destination from `EXCAT_PUBLIC_URL` | 1/3 | Low |
| S | Replay, or login injection (attacker's assertion) | `InResponseTo` must match a stored, unused request ID ≤ 10 min. Assertion-ID replay cache. IdP-initiated off | 1/3 | Low |
| S | Forged or substituted OIDC ID token | Signature against the issuer's JWKS, asymmetric algorithms only (`none`/HMAC refused), `iss`, `aud`/`azp`, `exp`/`iat`, `nonce` bound to the stored request | 1/3 | Low |
| S | OIDC code interception or login CSRF | PKCE S256 (verifier encrypted server-side), hashed single-use `state` ≤ 10 min, confidential client, redirect URI from `EXCAT_PUBLIC_URL` | 1/3 | Low |
| I | OIDC discovery used for SSRF or to redirect the token request | Issuer must be https on an Okta domain or the allowlist; every discovered endpoint must be on the issuer host | 1/2 | Low |
| E | IdP identity takes over a break-glass account | SSO/SCIM can never bind to local accounts | 1/3 | Low |
| E | Over-provisioning via groups | Roles only from explicit group mappings. Unmapped users have no access. Mapping a role requires holding its permissions | 2/2 | Low |
| S | Stolen SCIM token | Shown once, stored hashed, revocable, last-used visible. Bearer only on `/scim/v2`. Every change audited | 2/2 | Medium (rotate tokens; restrict SailPoint egress IPs at WAF) |

## TB3 — Public sources ↔ App (CVE data, news)

| STRIDE | Threat | Controls | L/I | Residual |
|---|---|---|---|---|
| T | Poisoned or truncated feed (mass KEV removal) | Schema parsing. KEV refuses < 100 entries. Per-field provenance. Timeline of changes | 1/2 | Low |
| T | XXE / entity bombs in feeds | `defusedxml` rejects entities | 1/3 | Low |
| I | SSRF via feed URLs or redirects | https only, single-host allowlist, DNS/private-range checks, redirect re-validation, Network Firewall | 1/3 | Low |
| D | Source outage or rate limiting | Retries with backoff, `Retry-After`, per-source health, alarms, partial-progress commits | 2/2 | Low |

## TB4 — Security tools ↔ App

| STRIDE | Threat | Controls | L/I | Residual |
|---|---|---|---|---|
| I | Credential theft from the database | Fernet-encrypted secrets (key in Secrets Manager/KMS), write-only APIs, rotation command | 1/3 | Low |
| E | Over-privileged service accounts | Guides require read-only roles and scopes | 2/3 | Medium (customer process) |
| T | Malicious tool data (XSS, formula injection) | Text rendering. Column truncation. Excel formula guard. Hardened XML parsing | 1/2 | Low |
| I | SSRF via connector base URL | Vendor-domain pinning, private/metadata blocking, same-host pagination | 1/3 | Low |
| D | Slow or failing tool blocks correlation | Per-tool isolation, timeouts, result caps, caching | 2/1 | Low |

## TB5 — App ↔ Data tier and AWS services

| STRIDE | Threat | Controls | L/I | Residual |
|---|---|---|---|---|
| T | Audit log tampering | Hash chain + `audit-verify`. PostgreSQL trigger blocks UPDATE/DELETE. Recommended DML-only grants | 1/3 | Low |
| I | Data exposure at rest | Aurora/S3/ElastiCache/logs encrypted with a KMS CMK. Isolated subnets. TLS to DB and Redis | 1/3 | Low |
| E | Compromised task pivots in AWS | Per-service task roles (S3 exports prefix, optional Bedrock). VPC endpoints. No ECS Exec in prod | 1/3 | Low |
| T | Template SSTI by a template author | Jinja `ImmutableSandboxedEnvironment` + autoescape. Test render on save. Approval workflow | 1/3 | Low |

## TB6 — App ↔ Outbound recipients and processors

| STRIDE | Threat | Controls | L/I | Residual |
|---|---|---|---|---|
| I | Advisory sent to the wrong people | Approval workflow. Confirmation dialog listing every recipient. Distribution lists. Audit | 2/2 | Low |
| T | Email header injection | CR/LF stripping. Validated addresses. BCC only in the envelope | 1/2 | Low |
| I | Asset identifiers leaked to AI vendors | Off by default. Provider allowlist. Redaction (hostnames, IPs, owners, emails, cloud IDs). Bedrock option. No prompt storage | 2/3 | Low–Medium (depends on policy) |
| T/E | Prompt injection from CVE/news/tool text | Fenced untrusted data, hardened system prompt, no tools, schema-validated and grounded outputs, human approval for advisories | 2/2 | Low |
| I | Exfiltration via AI-rendered images or links | No raw HTML or images rendered. CSP `img-src 'self' data:`. Links open with `noopener` | 1/2 | Low |
| I | Webhook URL abuse | Encrypted, write-only, Slack/Teams hosts only | 1/2 | Low |

## Out of scope and assumptions

Compromise of Okta, SailPoint or AWS control planes. Endpoint security of user workstations. Insider with
database-admin rights (mitigated by audit and grants). Supply-chain risk is reduced by pinned dependencies,
`pip-audit`, `npm audit`, Trivy IaC scanning and immutable, scanned ECR images.

Review this model at each release and whenever a new integration, data store or trust boundary is added.

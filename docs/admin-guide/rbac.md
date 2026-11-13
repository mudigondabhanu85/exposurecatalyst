# Users & RBAC administration

Authorization is enforced **server-side on every API endpoint** by `require(<permission>)` dependencies.
Hiding a button in the UI is only a convenience. An automated test asserts that no `/api` route except
health and login is reachable anonymously.

## Default roles

See the generated [roles × permissions matrix](../reference/rbac-matrix.md). System roles are read-only and
re-synchronized on every start, so upgrades can add permissions safely.

## Segregation of duties

| Duty | Admin | Security Analyst | Approver |
|---|:-:|:-:|:-:|
| Configure platform | ✅ | — | — |
| Draft and send advisories | — | ✅ | — |
| Approve advisories | — | — | ✅ |

Phase 2 also enforces that the approver of an advisory can't be its author.

## Escalation guard

- You can't grant a role whose permissions you don't hold yourself. For example, an Admin can't create a
  Super Admin, or a Security Analyst.
- You can't change your own roles or deactivate yourself.
- Changing someone's roles **signs them out everywhere**, so new permissions apply immediately.

## SailPoint / Okta group mapping

Users who sign in with Okta (SAML) or are provisioned by SailPoint (SCIM) get roles **only** through
group → role mappings in **Settings → Identity & SSO** (`sso:manage` and `role:manage`):

- A user's groups come from the SAML `groups` attribute, or from SCIM group membership for SCIM-provisioned
  users.
- A user whose groups map to no role **cannot sign in**.
- Changing a mapping recomputes all SSO users' roles at once and revokes the sessions of anyone whose roles
  changed.
- Manual role assignment is refused for SSO users (`409`), so the mapping stays the single source of truth.
- You can only map a role whose permissions you hold yourself.

Example mappings and SoD guidance are in the [SailPoint guide](sailpoint.md#group-role-mapping-examples).

## Local accounts and break-glass

Local accounts are for break-glass use. Day-to-day access should go through [Okta SSO](okta-saml.md).
Create the first local account with the CLI:

```bash
exposurecatalyst create-admin --username breakglass --email secops@example.com
```

TOTP is enrolled at creation. When `EXCAT_REQUIRE_MFA_FOR_LOCAL_ADMINS=true` (the default), a local account
can't call admin APIs from a session that wasn't MFA-verified. Store the break-glass password in your
enterprise vault and review its use in the audit log (`auth.login`).

## Account lockout

After `EXCAT_LOGIN_MAX_ATTEMPTS` (5) failures, the account locks for `EXCAT_LOGIN_LOCKOUT_MINUTES` (15). Error
messages are generic, so they don't reveal whether a username exists. Per-IP rate limiting
(`EXCAT_LOGIN_RATE_LIMIT_PER_MINUTE`) also applies. In AWS, add an AWS WAF rate-based rule as well. Admins can
**Unlock** early from Settings → Users & RBAC.

## Custom roles

**Settings → Users & RBAC → Custom roles** (`role:manage`): create a role, tick its permissions, edit or
delete it. System roles are read-only. A role still assigned to users can't be deleted. For example, a
*Vulnerability Manager* role with `cve:view`, `cve:refresh` and `advisory:approve`.
API: `POST/PUT/DELETE /api/admin/roles`.

## Audit

Every login (success and failure), lockout, user creation, role change, status change, source change and
refresh request is written to the hash-chained audit log. Verify its integrity with:

```bash
exposurecatalyst audit-verify
```

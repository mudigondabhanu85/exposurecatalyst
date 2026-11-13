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

## Local accounts and break-glass

Local accounts are meant for break-glass use; SSO arrives in Phase 4. Create the first one with the CLI:

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

`POST /api/admin/roles` and `PUT /api/admin/roles/{id}` need `role:manage`. The editing UI ships in Phase 4,
together with SailPoint group → role mapping.

## Audit

Every login (success and failure), lockout, user creation, role change, status change, source change and
refresh request is written to the hash-chained audit log. Verify its integrity with:

```bash
exposurecatalyst audit-verify
```

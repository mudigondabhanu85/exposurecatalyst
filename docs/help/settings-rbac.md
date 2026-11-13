---
id: settings-rbac
title: Settings — Users & RBAC
page: /settings/rbac
permission: user:manage
summary: Manage local users, assign roles and review the roles × permissions matrix.
keywords: [rbac, roles, permissions, users, unlock, segregation of duties]
docs: admin-guide/rbac/
---

## What this page is for

Controls who can do what. Every API endpoint enforces these permissions on the server, so hiding a
button is never the only protection.

## How to use it

1. **Review the matrix.** Each column is a role and each row is a permission. System roles are read-only.
2. **Create a local user.** Click **Add user** and enter a username, an optional email, an initial password
   (12+ characters) and one or more roles.
3. **Change a user's roles.** Pick roles in the user row. The user's existing sessions are signed out so the
   new permissions apply at their next login.
4. **Unlock a user.** After 5 failed logins an account locks for 15 minutes. Click **Unlock** to clear it
   early.

<!-- requires: role:manage -->
### Custom roles (Super Admin)

Use **New role** to combine permissions, for example a "Vulnerability Manager" with `cve:*` plus
`advisory:approve`. Keep segregation of duties: one person shouldn't both approve and send the same
advisory.
<!-- /requires -->

## Fields and columns

| Field | Meaning |
|---|---|
| Local | Account authenticates with a password stored here (break-glass). SSO users arrive in Phase 4. |
| MFA | TOTP is enrolled. Local admins must enrol before using admin pages. |
| Locked | The account is temporarily locked after repeated failed logins. |

## Required permissions

`user:manage` to view users and assign roles. `role:manage` to create or edit custom roles. You can't grant
a permission you don't hold yourself, and you can't change your own roles.

## Common errors

- **403 "Cannot grant permissions you do not hold"**: you're trying to assign a role that's more privileged
  than your own. Ask a Super Admin.
- **403 "MFA enrolment required"**: enrol TOTP from the user menu, then sign in again.

## Learn more

See [RBAC administration](../admin-guide/rbac.md) and the [matrix](../reference/rbac-matrix.md).

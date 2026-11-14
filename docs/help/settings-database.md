---
id: settings-database
title: Settings — Database
page: /settings/database
permission: settings:manage
summary: Check the database connection, TLS, pending migrations and whether the app runs with a least-privilege role.
keywords: [database, postgresql, mysql, sql server, oracle, sqlite, migrations, tls, pool, least privilege, redis]
docs: getting-started/installation/
---

## What this page is for

Shows the database ExposureCatalyst is connected to, tests the connection, lists pending schema migrations and
checks that the application role can't change the schema or rewrite the audit log.

## How to use it

1. Click **Test connection** to check connectivity and round-trip time.
2. Check **TLS**: it should say *In use* for any database that isn't on the same host.
3. **Schema migrations** should say *Up to date*. After an upgrade, run the migration task (production) or
   **Apply pending migrations** (single-node or dev installs where the app role may change the schema).
4. **Least privilege** should say *DML-only role* in production. If it says *Over-privileged*, follow the note.

## Fields

| Field | Meaning |
|---|---|
| Engine / driver | SQLAlchemy dialect and driver in use, and the server version |
| Password | Only whether one is configured. It is never shown |
| TLS | Whether this connection is encrypted (PostgreSQL), and the configured mode |
| Pool | Pool size, overflow, recycle time and connections in use (per process) |
| Least privilege | PostgreSQL check of the connected role: superuser, role/database creation, table ownership, schema CREATE, audit-log UPDATE/DELETE |

## Why the connection isn't editable here

The connection comes from `EXCAT_DATABASE_URL` and `EXCAT_DATABASE_PASSWORD` (environment or secret
store). Keeping it out of the UI means database credentials are never stored in the database they unlock,
and a browser session can't point the application at another server. To change it, update the deployment
configuration and restart.

## Required permissions

`settings:manage`.

## Common errors

- **Unreachable**: check the host, security groups, and that the password secret is current.
- **"The application runs with a DML-only role, so it cannot change the schema"**: expected in production.
  Run `exposurecatalyst migrate --app-role excat_app` as the database owner (the Terraform migration task).

## Learn more

See [Installation](../getting-started/installation.md) and [Runbooks](../operations/runbooks.md) (RB-10 backup and
restore, RB-12 upgrades).

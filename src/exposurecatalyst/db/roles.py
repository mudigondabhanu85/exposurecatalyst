"""Least-privilege runtime database role (PostgreSQL).

`exposurecatalyst migrate --app-role excat_app` runs as the migration (owner/master) user and, after Alembic:

* creates the role if missing (LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOINHERIT) and sets its password
  from ``EXCAT_APP_DB_PASSWORD`` (also how the password is rotated)
* grants CONNECT on the database, USAGE on the schema, SELECT/INSERT/UPDATE/DELETE on every table and
  USAGE/SELECT on every sequence — **no** CREATE, TRUNCATE, REFERENCES or TRIGGER
* restricts ``audit_log`` to SELECT/INSERT (append-only even without the immutability trigger)
* sets default privileges so tables created by later migrations get the same grants

The application services connect as this role; only the migration task holds the master credentials.
"""

from __future__ import annotations

import re

from sqlalchemy import text
from sqlalchemy.engine import Engine

ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
APPEND_ONLY_TABLES = ("audit_log",)


class RoleError(ValueError):
    pass


def _ident(name: str) -> str:
    if not ROLE_NAME.match(name):
        raise RoleError("role name must match ^[a-z_][a-z0-9_]{0,62}$")
    return f'"{name}"'


def _literal(value: str) -> str:
    """Standard-conforming SQL string literal (DDL such as ALTER ROLE … PASSWORD cannot use bind parameters)."""
    if "\x00" in value:
        raise RoleError("password must not contain NUL")
    return "'" + value.replace("'", "''") + "'"


def validate(role: str, password: str) -> None:
    """Fail fast (before any migration runs) on a bad role name or weak password."""
    grant_statements(role, password, "validate")


def grant_statements(role: str, password: str, database: str, schema: str = "public",
                     owner: str | None = None) -> list[str]:
    if len(password) < 16:
        raise RoleError("the application database password must be at least 16 characters")
    r, db, s = _ident(role), _ident(database), _ident(schema)
    stmts = [
        # DDL cannot use bind parameters: identifiers are regex-validated (_ident) and literals escaped (_literal).
        f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {_literal(role)}) THEN "  # noqa: S608  # nosec B608
        f"CREATE ROLE {r} LOGIN; END IF; END $$",
        f"ALTER ROLE {r} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION "
        f"PASSWORD {_literal(password)}",
        f"REVOKE CREATE ON SCHEMA {s} FROM PUBLIC",
        f"GRANT CONNECT ON DATABASE {db} TO {r}",
        f"GRANT USAGE ON SCHEMA {s} TO {r}",
        f"REVOKE ALL ON ALL TABLES IN SCHEMA {s} FROM {r}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {s} TO {r}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {s} TO {r}",
    ]
    stmts += [f"REVOKE UPDATE, DELETE ON TABLE {s}.{_ident(t)} FROM {r}" for t in APPEND_ONLY_TABLES]
    by = f" FOR ROLE {_ident(owner)}" if owner else ""
    stmts += [
        f"ALTER DEFAULT PRIVILEGES{by} IN SCHEMA {s} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {r}",
        f"ALTER DEFAULT PRIVILEGES{by} IN SCHEMA {s} GRANT USAGE, SELECT ON SEQUENCES TO {r}",
    ]
    return stmts


def ensure_app_role(engine: Engine, role: str, password: str) -> list[str]:
    """Apply the grants. Returns the statements with the password redacted (for logs)."""
    if engine.dialect.name != "postgresql":
        raise RoleError("--app-role is supported on PostgreSQL only; create a DML-only user manually elsewhere")
    with engine.begin() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        owner = conn.execute(text("SELECT current_user")).scalar_one()
        if owner == role:
            raise RoleError("run migrations as the owner/master user, not as the application role")
        stmts = grant_statements(role, password, database, owner=owner)
        for stmt in stmts:
            conn.exec_driver_sql(stmt)
    return [re.sub(r"PASSWORD '.*'$", "PASSWORD '***'", s) for s in stmts]

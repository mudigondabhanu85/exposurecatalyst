"""Settings → Database: connection status, test, migration status and runtime-role privilege check.

The connection itself is deployment configuration (``EXCAT_DATABASE_URL`` / ``EXCAT_DATABASE_PASSWORD`` from
the environment or Secrets Manager), deliberately **not** editable in the UI: storing database credentials
in the database they unlock, or letting a web request repoint the app at another server, would create a
credential store and an SSRF/takeover path. This page shows what is configured (password never returned),
tests it, reports pending migrations and whether the app runs with least privilege.
"""

from __future__ import annotations

import time
from typing import Any

from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.engine import make_url

from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_engine
from exposurecatalyst.security import audit
from exposurecatalyst.security.rbac import Permission as P

router = APIRouter(prefix="/api/settings/database", tags=["settings"])

ENGINES = [
    {"engine": "PostgreSQL 13+", "recommended": True, "extra": None,
     "url": "postgresql+psycopg://USER@HOST:5432/DB?sslmode=verify-full",
     "managed": "Amazon RDS / Aurora PostgreSQL, Azure Database for PostgreSQL, Google Cloud SQL"},
    {"engine": "MySQL 8 / MariaDB 10.6+", "recommended": False, "extra": "mysql",
     "url": "mysql+pymysql://USER@HOST:3306/DB?ssl_ca=/path/ca.pem",
     "managed": "Amazon RDS / Aurora MySQL, Azure, Cloud SQL"},
    {"engine": "Microsoft SQL Server 2019+", "recommended": False, "extra": "mssql",
     "url": "mssql+pyodbc://USER@HOST:1433/DB?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes",
     "managed": "Azure SQL Database, Amazon RDS for SQL Server"},
    {"engine": "Oracle 19c+", "recommended": False, "extra": "oracle",
     "url": "oracle+oracledb://USER@HOST:1521/?service_name=SVC", "managed": "Amazon RDS for Oracle, OCI"},
    {"engine": "SQLite", "recommended": False, "extra": None, "url": "sqlite:///./exposurecatalyst.db",
     "managed": "Development only — refused when EXCAT_ENV=prod"},
]


def _migration_status(conn) -> dict[str, Any]:
    from exposurecatalyst.cli import _alembic_config

    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    current = MigrationContext.configure(conn).get_current_heads()
    pending = []
    if set(current) != set(heads):
        for rev in script.iterate_revisions(heads, current[0] if current else "base"):
            if rev.revision not in current:
                pending.append({"revision": rev.revision, "message": (rev.doc or "").strip()})
    return {"current": list(current), "head": list(heads), "pending": list(reversed(pending)),
            "up_to_date": set(current) == set(heads)}


def _privileges(conn, dialect: str) -> dict[str, Any]:
    """Least-privilege check of the *connected* role (PostgreSQL; other engines report 'unknown')."""
    if dialect != "postgresql":
        return {"checked": False, "least_privilege": None,
                "note": "Privilege check is available on PostgreSQL. Use a DML-only user on other engines."}
    row = conn.execute(text(
        "SELECT r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, "
        "has_schema_privilege(current_user, 'public', 'CREATE') AS can_ddl, "
        "has_table_privilege(current_user, 'audit_log', 'UPDATE') AS audit_update, "
        "has_table_privilege(current_user, 'audit_log', 'DELETE') AS audit_delete, "
        "EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user) AS owns_tables "
        "FROM pg_roles r WHERE r.rolname = current_user"
    )).mappings().one()
    issues = []
    if row["rolsuper"]:
        issues.append("connected as a superuser")
    if row["rolcreaterole"] or row["rolcreatedb"]:
        issues.append("role can create roles or databases")
    if row["owns_tables"]:
        issues.append("role owns the tables (it can alter or drop them)")
    elif row["can_ddl"]:
        issues.append("role can create objects in the schema")
    if row["audit_update"] or row["audit_delete"]:
        issues.append("role can UPDATE/DELETE the audit log")
    return {"checked": True, "role": row["rolname"], "least_privilege": not issues, "issues": issues,
            "note": None if not issues else
            "Run the app as a DML-only role: exposurecatalyst migrate --app-role excat_app (see Installation)."}


def _server_info(conn, dialect: str) -> dict[str, Any]:
    info: dict[str, Any] = {"version": None, "tls": None}
    try:
        if dialect == "postgresql":
            info["version"] = conn.execute(text("SHOW server_version")).scalar()
            info["tls"] = conn.execute(text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")).scalar()
        elif dialect == "sqlite":
            info["version"] = conn.execute(text("select sqlite_version()")).scalar()
        elif dialect in ("mysql", "mariadb"):
            info["version"] = conn.execute(text("SELECT VERSION()")).scalar()
        else:
            info["version"] = getattr(conn.dialect, "server_version_info", None)
    except Exception as exc:  # noqa: BLE001 - informational only
        info["version_error"] = type(exc).__name__
    return info


@router.get("")
def database_status(_: Principal = Depends(require(P.SETTINGS_MANAGE)),
                    settings: Settings = Depends(settings_dep)) -> dict:
    url = make_url(settings.database_url.get_secret_value())
    engine = get_engine()
    dialect = engine.dialect.name
    out: dict[str, Any] = {
        "engine": dialect, "driver": url.drivername, "host": url.host, "port": url.port, "database": url.database,
        "username": url.username, "password_configured": bool(url.password),
        "tls_mode": url.query.get("sslmode") or url.query.get("ssl_mode") or url.query.get("Encrypt"),
        "pool": None if dialect == "sqlite" else {
            "size": settings.db_pool_size, "max_overflow": settings.db_max_overflow,
            "recycle_seconds": settings.db_pool_recycle_seconds,
            "checked_out": engine.pool.checkedout() if hasattr(engine.pool, "checkedout") else None,
        },
        "env": settings.env, "dev_only": dialect == "sqlite", "engines": ENGINES,
        "redis": {"used": False,
                  "note": "Not required: the scheduler is coordinated through the database. Redis is only "
                          "needed for the optional Celery worker mode (the scale extra)."},
    }
    try:
        with engine.connect() as conn:
            out |= {"connected": True, "error": None, **_server_info(conn, dialect),
                    "migrations": _migration_status(conn), "privileges": _privileges(conn, dialect)}
    except Exception as exc:  # noqa: BLE001
        out |= {"connected": False, "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"}
    return out


@router.post("/test")
def test_connection(request: Request, p: Principal = Depends(require(P.SETTINGS_MANAGE))) -> dict:
    engine = get_engine()
    started = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        ok, message = True, "Connected"
    except Exception as exc:  # noqa: BLE001
        ok, message = False, f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
    ms = round((time.perf_counter() - started) * 1000, 1)
    return {"ok": ok, "message": message, "latency_ms": ms}


@router.post("/migrate")
def run_migrations(request: Request, p: Principal = Depends(require(P.SETTINGS_MANAGE)),
                   settings: Settings = Depends(settings_dep)) -> dict:
    """Apply pending migrations from the UI — only where the connected role may run DDL (single-node / dev).
    In production the app's DML-only role cannot, by design: use the migration task."""
    engine = get_engine()
    with engine.connect() as conn:
        status = _migration_status(conn)
        privs = _privileges(conn, engine.dialect.name)
    if status["up_to_date"]:
        return {"ok": True, "message": "Already up to date", "migrations": status}
    if privs.get("checked") and privs.get("least_privilege"):
        raise HTTPException(409, "The application runs with a DML-only role, so it cannot change the schema. "
                                 "Run the migration task: exposurecatalyst migrate --app-role … as the owner.")
    from alembic import command

    from exposurecatalyst.cli import _alembic_config

    try:
        command.upgrade(_alembic_config(), "head")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"Migration failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    from exposurecatalyst.db.session import get_session_factory

    with get_session_factory()() as db:
        audit.record(db, "settings.database_migrated", actor=p.user, request=request, target_type="settings",
                     target_id="database", details={"applied": [m["revision"] for m in status["pending"]]})
        db.commit()
    with engine.connect() as conn:
        applied = len(status["pending"])
        return {"ok": True, "message": f"Applied {applied} migration(s)", "migrations": _migration_status(conn)}

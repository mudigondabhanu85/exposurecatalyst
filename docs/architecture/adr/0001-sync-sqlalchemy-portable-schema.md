# ADR-0001: Sync SQLAlchemy with a portable schema

**Status:** Accepted · **Date:** 2026-11-13

## Context
The platform must support PostgreSQL (default), MySQL, MariaDB, SQL Server, Oracle and SQLite. Async driver
support is uneven across these engines (mature for PostgreSQL, limited or absent elsewhere). The workload
is dominated by background ingestion and modest interactive traffic.

## Decision
Use **SQLAlchemy 2.x in synchronous mode**. FastAPI runs sync endpoints in its threadpool. Use only portable
column types and named constraints (a naming convention on `MetaData`), batch `IN` lists to ≤ 500, and avoid
dialect-specific SQL. The one exception is the opt-in PostgreSQL audit trigger in migration 0001.

## Consequences
- ✅ One code path for every supported engine, and simpler debugging and testing.
- ✅ Alembic migrations work everywhere (batch mode for SQLite).
- ⚠️ Thread-per-request concurrency. This is adequate for the expected load, and scaling out is horizontal
  (more API tasks).
- ⚠️ No DB-specific features like PostgreSQL full-text search. Keyword search uses escaped `ILIKE`. A
  search index (OpenSearch or PostgreSQL FTS behind an interface) can be added later.

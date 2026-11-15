"""`exposurecatalyst` command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import UTC, datetime

from exposurecatalyst.config import PROJECT_ROOT, get_settings


def _alembic_config():
    import os
    from pathlib import Path

    from alembic.config import Config

    root = Path(os.environ.get("EXCAT_APP_ROOT", PROJECT_ROOT))  # /app in the container image
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    return cfg


def cmd_migrate(args) -> int:
    import os

    from alembic import command

    if args.app_role:
        from exposurecatalyst.db.roles import RoleError, validate

        try:
            validate(args.app_role, os.environ.get("EXCAT_APP_DB_PASSWORD", ""))
        except RoleError as exc:
            print(f"App role not configured: {exc} (EXCAT_APP_DB_PASSWORD)", file=sys.stderr)
            return 2
    command.upgrade(_alembic_config(), args.revision)
    from exposurecatalyst.db.session import init_engine
    from exposurecatalyst.main import bootstrap

    engine = init_engine(get_settings())
    bootstrap(get_settings())
    print("Database migrated and seeded.")
    if args.app_role:
        from exposurecatalyst.db.roles import RoleError, ensure_app_role

        password = os.environ.get("EXCAT_APP_DB_PASSWORD", "")
        try:
            ensure_app_role(engine, args.app_role, password)
        except RoleError as exc:
            print(f"App role not configured: {exc}", file=sys.stderr)
            return 2
        print(f"Runtime role {args.app_role!r}: DML only, audit_log append-only.")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("exposurecatalyst.main:app_factory", factory=True, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips=args.forwarded_allow_ips, reload=args.reload,
                workers=None if args.reload else args.workers)
    return 0


def cmd_bootstrap(_args) -> int:
    from exposurecatalyst.bootstrap import run

    return run()


def cmd_healthcheck(args) -> int:
    """Container healthchecks without curl/wget in the image."""
    import time
    import urllib.request

    if args.target == "scheduler":
        from exposurecatalyst.ingestion.scheduler import HEARTBEAT

        if HEARTBEAT is None:
            print("EXCAT_SCHEDULER_HEARTBEAT is not set", file=sys.stderr)
            return 1
        try:
            age = time.time() - HEARTBEAT.stat().st_mtime
        except OSError:
            return 1
        return 0 if age < args.max_age else 1
    from urllib.parse import urlsplit

    parts = urlsplit(args.url)
    if parts.scheme not in ("http", "https") or parts.hostname not in ("127.0.0.1", "localhost", "::1"):
        print("healthcheck URL must be http(s) on loopback", file=sys.stderr)
        return 2
    try:
        with urllib.request.urlopen(args.url, timeout=3) as r:  # noqa: S310  # nosec B310 - scheme/host checked above
            return 0 if r.status == 200 else 1
    except OSError:
        return 1


def cmd_scheduler(_args) -> int:
    from exposurecatalyst.db.session import init_engine
    from exposurecatalyst.ingestion.scheduler import run_forever
    from exposurecatalyst.logging import configure_logging

    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    init_engine(s)
    run_forever(s)
    return 0


def cmd_ingest(args) -> int:
    from exposurecatalyst.db.session import get_session_factory, init_engine, session_scope
    from exposurecatalyst.ingestion.nvd import NvdSource
    from exposurecatalyst.ingestion.service import run_source
    from exposurecatalyst.logging import configure_logging
    from exposurecatalyst.models import SourceState

    s = get_settings()
    configure_logging(s.log_level, json_logs=False)
    init_engine(s)
    if args.source == "nvd" and args.since:
        start = datetime.fromisoformat(args.since).replace(tzinfo=UTC)
        src = NvdSource(s)
        try:
            with session_scope() as db:
                state = db.get(SourceState, "nvd")
                res = src.ingest_range(db, state, start, datetime.now(UTC))
        finally:
            src.close()
        print(f"nvd backfill: {res.records} records {res.detail}")
        return 0
    job = run_source(args.source, "cli", s, get_session_factory())
    if job is None:
        print("Source is already running elsewhere.")
        return 1
    print(f"{args.source}: {job.status} ({job.records} records){' — ' + job.error if job.error else ''}")
    return 0 if job.status == "ok" else 1


def cmd_create_admin(args) -> int:
    import pyotp
    from sqlalchemy import select

    from exposurecatalyst.db.session import init_engine, session_scope
    from exposurecatalyst.models import Role, User
    from exposurecatalyst.security import audit
    from exposurecatalyst.security.crypto import get_secret_box
    from exposurecatalyst.security.passwords import hash_password, password_problems
    from exposurecatalyst.security.rbac import seed_roles

    s = get_settings()
    init_engine(s)
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    problems = password_problems(password, username=args.username, min_length=s.password_min_length)
    if problems:
        print("Password " + "; ".join(problems), file=sys.stderr)
        return 1
    secret = pyotp.random_base32()
    with session_scope() as db:
        seed_roles(db)
        if db.scalar(select(User).where(User.username == args.username)):
            print("User already exists.", file=sys.stderr)
            return 1
        role = db.scalar(select(Role).where(Role.name == args.role))
        if role is None:
            print(f"Unknown role {args.role}", file=sys.stderr)
            return 1
        user = User(username=args.username, email=args.email, display_name=args.username,
                    password_hash=hash_password(password), is_local=True, roles=[role],
                    totp_secret_enc=get_secret_box().encrypt(secret), totp_enabled=not args.no_mfa)
        db.add(user)
        db.flush()
        audit.record(db, "user.created", actor_username="cli", target_type="user", target_id=user.id,
                     details={"username": user.username, "roles": [role.name], "via": "cli"})
    print(f"Created {args.username} with role '{args.role}'.")
    if not args.no_mfa:
        uri = pyotp.TOTP(secret).provisioning_uri(name=args.username, issuer_name="ExposureCatalyst")
        print("Add this TOTP to your authenticator app (shown once):")
        print(f"  secret: {secret}\n  uri:    {uri}")
    return 0


def cmd_gen_key(_args) -> int:
    from cryptography.fernet import Fernet

    print(Fernet.generate_key().decode())
    return 0


def cmd_audit_verify(_args) -> int:
    from exposurecatalyst.db.session import init_engine, session_scope
    from exposurecatalyst.security.audit import verify_chain

    init_engine(get_settings())
    with session_scope() as db:
        ok, bad, n = verify_chain(db)
    print(f"Audit chain {'OK' if ok else 'BROKEN at id ' + str(bad)} ({n} rows checked)")
    return 0 if ok else 2


def cmd_rotate_secrets(args) -> int:
    from exposurecatalyst.db.session import init_engine, session_scope
    from exposurecatalyst.maintenance import rotate_secrets

    s = get_settings()
    if s.encryption_key is None:
        print("EXCAT_ENCRYPTION_KEY must be set (the new primary key).", file=sys.stderr)
        return 1
    init_engine(s)
    with session_scope() as db:
        counts = rotate_secrets(db, dry_run=args.dry_run)
    summary = ", ".join(f"{k}={v}" for k, v in counts.items())
    print(("Dry run — would re-encrypt: " if args.dry_run else "Re-encrypted: ") + summary)
    if not args.dry_run:
        print("You can now remove the old key from EXCAT_ENCRYPTION_KEYS_PREVIOUS and redeploy.")
    return 0


def cmd_retention(_args) -> int:
    from exposurecatalyst.db.session import init_engine, session_scope
    from exposurecatalyst.maintenance import retention

    s = get_settings()
    init_engine(s)
    with session_scope() as db:
        counts = retention(db, s)
    print("Deleted: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


def cmd_docs(args) -> int:
    from exposurecatalyst.docs.build import main as docs_main

    return docs_main(args.docs_args)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="exposurecatalyst")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("migrate", help="Apply database migrations and seed roles")
    m.add_argument("revision", nargs="?", default="head")
    m.add_argument("--app-role", metavar="NAME",
                   help="PostgreSQL: create/update this DML-only runtime role (password from EXCAT_APP_DB_PASSWORD)")
    m.set_defaults(fn=cmd_migrate)

    sv = sub.add_parser("serve", help="Run the API server")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--reload", action="store_true")
    sv.add_argument("--forwarded-allow-ips", default="127.0.0.1",
                    help="Proxies trusted for X-Forwarded-For/Proto: IPs or CIDRs, comma-separated")
    sv.add_argument("--workers", type=int, default=int(os.environ.get("EXCAT_WEB_CONCURRENCY", "1")),
                    help="Worker processes (default 1; login rate limits are per process)")
    sv.set_defaults(fn=cmd_serve)

    sub.add_parser("bootstrap", help="Docker first start: generate missing secrets and a self-signed "
                   "certificate (never overwrites)").set_defaults(fn=cmd_bootstrap)
    hc = sub.add_parser("healthcheck", help="Container healthcheck")
    hc.add_argument("target", choices=["api", "scheduler"])
    hc.add_argument("--url", default="http://127.0.0.1:8000/api/health/live")
    hc.add_argument("--max-age", type=int, default=300, help="scheduler: max heartbeat age in seconds")
    hc.set_defaults(fn=cmd_healthcheck)

    sub.add_parser("scheduler", help="Run the ingestion scheduler").set_defaults(fn=cmd_scheduler)

    i = sub.add_parser("ingest", help="Run one source now")
    i.add_argument("source", choices=["nvd", "kev", "epss"])
    i.add_argument("--since", help="NVD only: backfill from this date (YYYY-MM-DD)")
    i.set_defaults(fn=cmd_ingest)

    a = sub.add_parser("create-admin", help="Create a local (break-glass) user with TOTP")
    a.add_argument("--username", required=True)
    a.add_argument("--email")
    a.add_argument("--role", default="Super Admin")
    a.add_argument("--no-mfa", action="store_true", help="Dev only: skip TOTP")
    a.set_defaults(fn=cmd_create_admin)

    sub.add_parser("gen-key", help="Generate an EXCAT_ENCRYPTION_KEY").set_defaults(fn=cmd_gen_key)
    sub.add_parser("audit-verify", help="Verify the audit log hash chain").set_defaults(fn=cmd_audit_verify)

    rs = sub.add_parser("rotate-secrets", help="Re-encrypt stored secrets under the current EXCAT_ENCRYPTION_KEY")
    rs.add_argument("--dry-run", action="store_true")
    rs.set_defaults(fn=cmd_rotate_secrets)
    sub.add_parser("retention", help="Apply data-retention rules now").set_defaults(fn=cmd_retention)

    d = sub.add_parser("docs", help="Build documentation (see `docs --help`)")
    d.add_argument("docs_args", nargs=argparse.REMAINDER)
    d.set_defaults(fn=cmd_docs)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

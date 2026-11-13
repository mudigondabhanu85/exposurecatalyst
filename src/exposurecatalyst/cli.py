"""`exposurecatalyst` command-line interface."""

from __future__ import annotations

import argparse
import getpass
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
    from alembic import command

    command.upgrade(_alembic_config(), args.revision)
    from exposurecatalyst.db.session import init_engine
    from exposurecatalyst.main import bootstrap

    init_engine(get_settings())
    bootstrap(get_settings())
    print("Database migrated and seeded.")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("exposurecatalyst.main:app_factory", factory=True, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips=args.forwarded_allow_ips, reload=args.reload)
    return 0


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


def cmd_docs(args) -> int:
    from exposurecatalyst.docs.build import main as docs_main

    return docs_main(args.docs_args)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="exposurecatalyst")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("migrate", help="Apply database migrations and seed roles")
    m.add_argument("revision", nargs="?", default="head")
    m.set_defaults(fn=cmd_migrate)

    sv = sub.add_parser("serve", help="Run the API server")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--reload", action="store_true")
    sv.add_argument("--forwarded-allow-ips", default="127.0.0.1")
    sv.set_defaults(fn=cmd_serve)

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

    d = sub.add_parser("docs", help="Build documentation (see `docs --help`)")
    d.add_argument("docs_args", nargs=argparse.REMAINDER)
    d.set_defaults(fn=cmd_docs)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

"""DML-only runtime role: statement generation and input validation (live grants are verified on PostgreSQL)."""

from __future__ import annotations

import pytest

from exposurecatalyst import cli
from exposurecatalyst.db.roles import RoleError, ensure_app_role, grant_statements, validate

PW = "a-long-enough-password-123"


def test_grants_are_dml_only_and_audit_log_append_only():
    stmts = grant_statements("excat_app", PW, "excat", owner="excat_admin")
    joined = "\n".join(stmts)
    assert 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "excat_app"' in joined
    assert 'REVOKE UPDATE, DELETE ON TABLE "public"."audit_log" FROM "excat_app"' in joined
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT" in joined
    assert 'ALTER DEFAULT PRIVILEGES FOR ROLE "excat_admin"' in joined
    for forbidden in ("TRUNCATE", "REFERENCES", "TRIGGER", "GRANT CREATE", "GRANT ALL", "SUPERUSER PASSWORD"):
        assert forbidden not in joined.replace("NOSUPERUSER", ""), forbidden
    # the audit_log revoke comes after the blanket table grant
    assert joined.index("REVOKE UPDATE, DELETE ON TABLE") > joined.index("GRANT SELECT, INSERT, UPDATE, DELETE")


def test_password_literal_is_escaped():
    stmts = grant_statements("excat_app", "it's'; DROP ROLE x; --pad", "excat")
    alter = next(s for s in stmts if s.startswith("ALTER ROLE"))
    assert alter.endswith("PASSWORD 'it''s''; DROP ROLE x; --pad'")


@pytest.mark.parametrize("role", ["", "Excat", "x; drop", 'a"b', "1abc", "a" * 64])
def test_bad_role_names_rejected(role):
    with pytest.raises(RoleError):
        validate(role, PW)


@pytest.mark.parametrize("pw", ["", "short", "x" * 15, "has\x00nul-long-enough-xx"])
def test_weak_or_invalid_passwords_rejected(pw):
    with pytest.raises(RoleError):
        validate("excat_app", pw)


def test_sqlite_is_refused(db_factory):
    from exposurecatalyst.db.session import get_engine

    with pytest.raises(RoleError, match="PostgreSQL only"):
        ensure_app_role(get_engine(), "excat_app", PW)


def test_migrate_validates_before_touching_the_database(monkeypatch, capsys):
    called = []
    monkeypatch.setattr("alembic.command.upgrade", lambda *a, **k: called.append(a))
    monkeypatch.setenv("EXCAT_APP_DB_PASSWORD", "short")
    assert cli.main(["migrate", "--app-role", "excat_app"]) == 2
    assert not called and "at least 16 characters" in capsys.readouterr().err

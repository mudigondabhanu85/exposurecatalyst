"""Docker deployment (Phase 1): *_FILE secrets, first-start bootstrap, container healthchecks."""

from __future__ import annotations

import json
import os
import time

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from exposurecatalyst import bootstrap
from exposurecatalyst.cli import main as cli
from exposurecatalyst.config import Settings


@pytest.fixture
def state(tmp_path, monkeypatch):
    for k in ("EXCAT_ENCRYPTION_KEY", "POSTGRES_PASSWORD", "REDIS_PASSWORD", "EXCAT_FQDN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("EXCAT_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("EXCAT_DB_SECRET_DIR", str(tmp_path / "db-secret"))
    monkeypatch.setenv("EXCAT_CERTS_DIR", str(tmp_path / "certs"))
    monkeypatch.setenv("EXCAT_BACKUPS_DIR", str(tmp_path / "backups-missing"))
    return tmp_path


def _sans(path):
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
        x509.DNSName)


# ---- EXCAT_<NAME>_FILE ------------------------------------------------------------------------------------

def test_file_source_fills_gaps_only(tmp_path, monkeypatch):
    f = tmp_path / "nvd"
    f.write_text("from-file\n")
    monkeypatch.setenv("EXCAT_ENV", "dev")
    monkeypatch.setenv("EXCAT_NVD_API_KEY_FILE", str(f))
    monkeypatch.delenv("EXCAT_NVD_API_KEY", raising=False)
    assert Settings(_env_file=None).nvd_api_key.get_secret_value() == "from-file"  # newline stripped
    monkeypatch.setenv("EXCAT_NVD_API_KEY", "")  # compose env_file with an empty value
    assert Settings(_env_file=None).nvd_api_key.get_secret_value() == "from-file"
    monkeypatch.setenv("EXCAT_NVD_API_KEY", "explicit")
    assert Settings(_env_file=None).nvd_api_key.get_secret_value() == "explicit"  # explicit always wins


def test_file_source_respects_dotenv_value(tmp_path, monkeypatch):
    f, env = tmp_path / "nvd", tmp_path / ".env"
    f.write_text("from-file")
    env.write_text("EXCAT_ENV=dev\nEXCAT_NVD_API_KEY=from-dotenv\n")
    monkeypatch.delenv("EXCAT_NVD_API_KEY", raising=False)
    monkeypatch.delenv("EXCAT_ENV", raising=False)
    monkeypatch.setenv("EXCAT_NVD_API_KEY_FILE", str(f))
    assert Settings(_env_file=env).nvd_api_key.get_secret_value() == "from-dotenv"


def test_file_source_unreadable_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("EXCAT_ENV", "dev")
    monkeypatch.delenv("EXCAT_DATABASE_PASSWORD", raising=False)
    monkeypatch.setenv("EXCAT_DATABASE_PASSWORD_FILE", "/nonexistent/db_password")
    with pytest.raises(ValueError, match="EXCAT_DATABASE_PASSWORD_FILE: cannot read"):
        Settings(_env_file=None)


def test_no_file_vars_means_unchanged_behaviour(monkeypatch):
    monkeypatch.setenv("EXCAT_ENV", "dev")
    for k in list(os.environ):
        if k.startswith("EXCAT_") and k.endswith("_FILE"):
            monkeypatch.delenv(k)
    s = Settings(_env_file=None)
    assert s.public_url == "http://localhost:8000" and s.nvd_api_key is None


def test_db_password_file_merges_into_url(tmp_path, monkeypatch):
    f = tmp_path / "pw"
    f.write_text("s3cr3t-pw\n")
    monkeypatch.setenv("EXCAT_ENV", "dev")
    monkeypatch.delenv("EXCAT_DATABASE_PASSWORD", raising=False)
    monkeypatch.setenv("EXCAT_DATABASE_URL", "postgresql+psycopg://excat@postgres:5432/excat")
    monkeypatch.setenv("EXCAT_DATABASE_PASSWORD_FILE", str(f))
    assert "excat:s3cr3t-pw@postgres" in Settings(_env_file=None).database_url.get_secret_value()


# ---- bootstrap -------------------------------------------------------------------------------------------

def test_bootstrap_generates_once_and_never_overwrites(state, capsys):
    assert bootstrap.run() == 0
    key = (state / "secrets" / "encryption_key").read_text()
    pw = (state / "db-secret" / "db_password").read_text()
    cert = (state / "certs" / "active" / "fullchain.pem").read_bytes()
    assert oct((state / "secrets" / "encryption_key").stat().st_mode & 0o777) == "0o600"
    assert len(pw.strip()) >= 32
    out = capsys.readouterr().out
    assert key.strip() not in out and pw.strip() not in out  # never prints secrets

    assert bootstrap.run() == 0
    assert (state / "secrets" / "encryption_key").read_text() == key
    assert (state / "db-secret" / "db_password").read_text() == pw
    assert (state / "certs" / "active" / "fullchain.pem").read_bytes() == cert
    assert "existing secret kept" in capsys.readouterr().out


def test_bootstrap_reuses_explicit_values(state, monkeypatch):
    monkeypatch.setenv("EXCAT_ENCRYPTION_KEY", "explicit-key")
    monkeypatch.setenv("POSTGRES_PASSWORD", "existing-db-password")
    bootstrap.run()
    assert not (state / "secrets" / "encryption_key").exists()  # .env key stays the only key
    assert (state / "db-secret" / "db_password").read_text().strip() == "existing-db-password"
    monkeypatch.setenv("POSTGRES_PASSWORD", "changed-later")
    assert "differs from POSTGRES_PASSWORD" in bootstrap.ensure_db_password(bootstrap.Paths.from_env())
    assert (state / "db-secret" / "db_password").read_text().strip() == "existing-db-password"


def test_self_signed_follows_fqdn_and_keeps_previous(state, monkeypatch):
    monkeypatch.setenv("EXCAT_FQDN", "excat.corp.example")
    bootstrap.run()
    active = state / "certs" / "active"
    assert _sans(active / "fullchain.pem") == ["excat.corp.example", "localhost"]
    assert json.loads((active / "meta.json").read_text())["mode"] == "self-signed"
    monkeypatch.setenv("EXCAT_FQDN", "new.corp.example.")
    msg = bootstrap.ensure_certificate(bootstrap.Paths.from_env(), bootstrap.configured_fqdn())
    assert "FQDN changed" in msg and _sans(active / "fullchain.pem")[0] == "new.corp.example"
    assert _sans(state / "certs" / "previous" / "fullchain.pem")[0] == "excat.corp.example"


def test_installed_certificate_is_never_replaced(state, monkeypatch):
    certs = state / "certs"
    cert, key = bootstrap.generate_self_signed("real.corp.example")
    bootstrap.write_active_cert(certs, cert, key, {"mode": "uploaded", "fqdn": "real.corp.example"})
    monkeypatch.setenv("EXCAT_FQDN", "other.corp.example")
    assert "kept" in bootstrap.ensure_certificate(bootstrap.Paths.from_env(), bootstrap.configured_fqdn())
    assert (certs / "active" / "fullchain.pem").read_bytes() == cert


def test_private_key_not_world_readable(state):
    bootstrap.run()
    mode = (state / "certs" / "active" / "privkey.pem").stat().st_mode & 0o777
    assert mode & 0o007 == 0


# ---- healthchecks / CLI ----------------------------------------------------------------------------------

def test_scheduler_healthcheck_uses_heartbeat(tmp_path, monkeypatch):
    from exposurecatalyst.ingestion import scheduler

    hb = tmp_path / "hb"
    monkeypatch.setattr(scheduler, "HEARTBEAT", hb)
    monkeypatch.setattr(scheduler, "HEARTBEAT", None)
    scheduler._heartbeat()  # unset → no file anywhere (local runs unchanged)
    assert cli(["healthcheck", "scheduler"]) == 1
    monkeypatch.setattr(scheduler, "HEARTBEAT", hb)
    assert cli(["healthcheck", "scheduler"]) == 1  # no heartbeat yet
    scheduler._heartbeat()
    assert cli(["healthcheck", "scheduler", "--max-age", "60"]) == 0
    old = time.time() - 600
    os.utime(hb, (old, old))
    assert cli(["healthcheck", "scheduler", "--max-age", "60"]) == 1


def test_api_healthcheck_unreachable_is_unhealthy():
    assert cli(["healthcheck", "api", "--url", "http://127.0.0.1:9/api/health/live"]) == 1
    assert cli(["healthcheck", "api", "--url", "file:///etc/passwd"]) == 2
    assert cli(["healthcheck", "api", "--url", "http://169.254.169.254/"]) == 2


def test_serve_accepts_workers_and_cidr(monkeypatch):
    seen = {}
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: seen.update(kw))
    assert cli(["serve", "--workers", "3", "--forwarded-allow-ips", "172.30.250.0/24"]) == 0
    assert seen["workers"] == 3 and seen["forwarded_allow_ips"] == "172.30.250.0/24" and seen["proxy_headers"]

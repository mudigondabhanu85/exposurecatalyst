"""Settings → Certificates & Domain: flags, RBAC, install/activate/rollback, CSR, trusted CA, ACME, expiry alerts,
migration 0008 upgrade/downgrade. The proxy is mocked at its two boundaries (admin reload + served fingerprint)."""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi.testclient import TestClient

from exposurecatalyst import tls
from exposurecatalyst.config import PROJECT_ROOT, Settings
from exposurecatalyst.db.base import Base
from exposurecatalyst.db.session import get_engine, get_session_factory
from exposurecatalyst.models import AuditLog, Role, TlsCertificate, User
from exposurecatalyst.security import certs
from exposurecatalyst.security.passwords import hash_password
from tests.test_certs import FQDN, _ca, _leaf, pem

PW = "Correct-Horse-Battery-9"


@pytest.fixture(scope="module")
def pki():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _ca("Corp Root CA", root_key)
    int_key = ec.generate_private_key(ec.SECP256R1())
    return {"root": root, "root_key": root_key, "int": _ca("Corp Issuing CA", int_key, root, root_key, 0),
            "int_key": int_key}


class Proxy:
    """Fake proxy: 'serves' whatever fullchain is in certs/active after each reload (or a stale cert if broken)."""

    def __init__(self, certs_dir):
        self.certs_dir, self.reloads, self.broken, self.loaded = certs_dir, 0, False, []

    def reload(self, caddyfile):
        self.reloads += 1
        self.loaded.append(caddyfile)

    def served(self, server_name, *a, **kw):
        if self.broken:
            return "0" * 64
        f = self.certs_dir / "active" / "fullchain.pem"
        return certs.fingerprint(x509.load_pem_x509_certificates(f.read_bytes())[0]) if f.exists() else None


def make(monkeypatch, tmp_path, **flags):
    s = Settings(env="test", database_url="sqlite://", cookie_secure=False, log_json=False, log_level="WARNING",
                 ssrf_resolve_dns=False, require_mfa_for_local_admins=False, fqdn=FQDN, certs_dir=tmp_path / "certs",
                 frontend_dist_dir=PROJECT_ROOT / "nonexistent", docs_site_dir=PROJECT_ROOT / "nonexistent",
                 features={"ui_tls_management": True, **flags})
    import exposurecatalyst.api.auth as auth_mod
    import exposurecatalyst.main  # noqa: F401
    from exposurecatalyst.security import crypto

    for name, mod in list(sys.modules.items()):
        if name.startswith("exposurecatalyst") and hasattr(mod, "get_settings"):
            monkeypatch.setattr(mod, "get_settings", lambda: s)
    crypto.get_secret_box.cache_clear()
    auth_mod._limiter = None
    from exposurecatalyst import bootstrap
    from exposurecatalyst.main import create_app
    from exposurecatalyst.security.rbac import seed_roles

    cert, key = bootstrap.generate_self_signed(FQDN)
    bootstrap.write_active_cert(s.certs_dir, cert, key, {"mode": "self-signed", "fqdn": FQDN})
    proxy = Proxy(s.certs_dir)
    monkeypatch.setattr(tls, "reload_proxy", proxy.reload)
    monkeypatch.setattr(tls, "served_fingerprint", proxy.served)
    monkeypatch.setattr(tls, "proxy_available", lambda: True)
    monkeypatch.setattr(tls.certs, "public_roots", lambda: [])  # the test PKI is the only trust
    app = create_app(s)
    Base.metadata.create_all(get_engine())
    with get_session_factory()() as db:
        seed_roles(db)
        for name, role in (("root", "Super Admin"), ("ana", "Security Analyst")):
            db.add(User(username=name, password_hash=hash_password(PW), email=f"{name}@corp.example",
                        roles=[db.query(Role).filter_by(name=role).one()]))
        db.commit()
    return app, s, proxy


def client(app, user="root"):
    c = TestClient(app, base_url=f"https://{FQDN}")
    c.__enter__()
    r = c.post("/api/auth/login", json={"username": user, "password": PW})
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def files(leaf=None, key=None, chain=None):
    out = {}
    if leaf is not None:
        out["cert"] = ("cert.pem", pem(leaf))
    if key is not None:
        out["key"] = ("key.pem", pem(key))
    if chain is not None:
        out["chain"] = ("chain.pem", pem(*chain))
    return out


@pytest.fixture
def env(monkeypatch, tmp_path, pki):
    app, s, proxy = make(monkeypatch, tmp_path)
    c = client(app)
    r = c.put("/api/settings/certificates/trusted-ca", files={"bundle": ("ca.pem", pem(pki["root"]))})
    assert r.status_code == 200, r.text
    return app, s, proxy, c


# ---- flags & RBAC ------------------------------------------------------------------------------------------

def test_flag_off_blocks_management_but_not_status(monkeypatch, tmp_path):
    app, s, _ = make(monkeypatch, tmp_path, ui_tls_management=False)
    c = client(app)
    st = c.get("/api/settings/certificates").json()
    assert st["active"]["mode"] == "self-signed" and st["features"]["ui_tls_management"] is False
    assert st["urls"]["SAML ACS URL"] == f"https://{FQDN}/api/auth/saml/acs"
    for method, path in (("post", "/api/settings/certificates/install"), ("post", "/api/settings/certificates/rollback"),
                         ("post", "/api/settings/certificates/csr"), ("delete", "/api/settings/certificates/trusted-ca")):
        assert getattr(c, method)(path).status_code == 403, path


def test_rbac(env):
    app, *_ = env
    assert TestClient(app, base_url=f"https://{FQDN}").get("/api/settings/certificates").status_code == 401
    assert client(app, "ana").get("/api/settings/certificates").status_code == 403


# ---- install / validate / rollback -------------------------------------------------------------------------

def test_validate_is_a_dry_run(env, pki):
    app, s, proxy, c = env
    leaf, key = _leaf(pki["int"], pki["int_key"])
    r = c.post("/api/settings/certificates/validate", files=files(leaf, key, [pki["int"]])).json()
    assert r["ok"] and r["info"]["covers_fqdn"] and proxy.reloads == 0
    with get_session_factory()() as db:
        assert db.query(TlsCertificate).count() == 0


def test_install_activates_hot_reloads_and_never_returns_key(env, pki):
    app, s, proxy, c = env
    leaf, key = _leaf(pki["int"], pki["int_key"])
    r = c.post("/api/settings/certificates/install", files=files(leaf, key, [pki["int"]]))
    assert r.status_code == 200, r.text
    assert proxy.reloads == 1 and r.json()["fingerprint"] == certs.fingerprint(leaf)
    active = s.certs_dir / "active"
    assert json.loads((active / "meta.json").read_text())["mode"] == "uploaded"
    assert (active / "fullchain.pem").read_bytes().count(b"BEGIN CERTIFICATE") == 2  # leaf + intermediate
    assert (s.certs_dir / "previous" / "meta.json").exists()  # self-signed kept for rollback
    st = c.get("/api/settings/certificates")
    assert "PRIVATE KEY" not in st.text and st.json()["active"]["mode"] == "uploaded"
    assert st.json()["history"][0]["status"] == "active"
    with get_session_factory()() as db:
        row = db.query(TlsCertificate).one()
        assert "PRIVATE KEY" not in row.key_enc  # encrypted at rest
        a = db.query(AuditLog).filter_by(action="tls.certificate_installed").one()
        assert a.actor_username == "root" and "PRIVATE" not in json.dumps(a.details)


def test_invalid_upload_rejected_and_nothing_changes(env, pki):
    app, s, proxy, c = env
    before = (s.certs_dir / "active" / "fullchain.pem").read_bytes()
    leaf, key = _leaf(pki["int"], pki["int_key"], names=("other.corp.example",))
    r = c.post("/api/settings/certificates/install", files=files(leaf, key, [pki["int"]]))
    assert r.status_code == 422 and "do not cover" in r.text
    assert (s.certs_dir / "active" / "fullchain.pem").read_bytes() == before and proxy.reloads == 0
    r = c.post("/api/settings/certificates/install", files=files(leaf, None, [pki["int"]]))
    assert r.status_code == 422 and "no private key" in r.text


def test_failed_activation_restores_previous(env, pki):
    app, s, proxy, c = env
    before = (s.certs_dir / "active" / "fullchain.pem").read_bytes()
    proxy.broken = True
    leaf, key = _leaf(pki["int"], pki["int_key"])
    r = c.post("/api/settings/certificates/install", files=files(leaf, key, [pki["int"]]))
    assert r.status_code == 502 and "previous certificate restored" in r.text
    assert (s.certs_dir / "active" / "fullchain.pem").read_bytes() == before
    with get_session_factory()() as db:
        assert db.query(TlsCertificate).one().status == "failed"


def test_rollback_to_generated_self_signed(env, pki):
    app, s, proxy, c = env
    leaf, key = _leaf(pki["int"], pki["int_key"])
    assert c.post("/api/settings/certificates/install", files=files(leaf, key, [pki["int"]])).status_code == 200
    r = c.post("/api/settings/certificates/rollback")  # previous = the self-signed cert (files only, no DB row)
    assert r.status_code == 200 and r.json()["mode"] == "self-signed"
    assert json.loads((s.certs_dir / "active" / "meta.json").read_text())["mode"] == "self-signed"
    assert c.get("/api/settings/certificates").json()["history"][0]["status"] == "previous"
    proxy.broken = True  # a failed rollback keeps the current certificate
    before = (s.certs_dir / "active" / "fullchain.pem").read_bytes()
    assert c.post("/api/settings/certificates/rollback").status_code == 502
    assert (s.certs_dir / "active" / "fullchain.pem").read_bytes() == before


def test_rollback_nothing_previous(monkeypatch, tmp_path):
    app, s, proxy = make(monkeypatch, tmp_path)
    c = client(app)
    assert c.post("/api/settings/certificates/rollback").status_code == 409  # fresh install: nothing to roll back to


def test_rollback(env, pki):
    app, s, proxy, c = env
    first, k1 = _leaf(pki["int"], pki["int_key"])
    second, k2 = _leaf(pki["int"], pki["int_key"])
    c.post("/api/settings/certificates/install", files=files(first, k1, [pki["int"]]))
    c.post("/api/settings/certificates/install", files=files(second, k2, [pki["int"]]))
    r = c.post("/api/settings/certificates/rollback")
    assert r.status_code == 200 and r.json()["fingerprint"] == certs.fingerprint(first)
    statuses = {h["fingerprint"]: h["status"] for h in c.get("/api/settings/certificates").json()["history"]}
    assert statuses[certs.fingerprint(first)] == "active" and statuses[certs.fingerprint(second)] == "previous"


def test_pkcs12_and_paste(env, pki):
    app, s, proxy, c = env
    leaf, key = _leaf(pki["int"], pki["int_key"])
    p12 = pkcs12.serialize_key_and_certificates(b"x", key, leaf, [pki["int"]],
                                                serialization.BestAvailableEncryption(b"pfx-pw"))
    assert c.post("/api/settings/certificates/install", files={"pfx": ("c.pfx", p12)},
                  data={"password": "wrong"}).status_code == 422
    assert c.post("/api/settings/certificates/install", files={"pfx": ("c.pfx", p12)},
                  data={"password": "pfx-pw"}).status_code == 200
    leaf2, key2 = _leaf(pki["int"], pki["int_key"])
    r = c.post("/api/settings/certificates/install", data={"pasted": (pem(leaf2, key2, pki["int"])).decode()})
    assert r.status_code == 200, r.text


# ---- CSR ---------------------------------------------------------------------------------------------------

def _sign_csr(csr_pem: bytes, pki) -> x509.Certificate:
    csr = x509.load_pem_x509_csr(csr_pem)
    now = dt.datetime.now(dt.UTC)
    return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(pki["int"].subject)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(days=90))
            .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pki["int_key"].public_key()),
                           critical=False)
            .sign(pki["int_key"], hashes.SHA256()))


def test_csr_flow_key_stays_on_server(env, pki):
    app, s, proxy, c = env
    r = c.post("/api/settings/certificates/csr", json={"common_name": FQDN, "sans": ["www." + FQDN],
                                                       "key_type": "rsa-3072", "organization": "Corp", "country": "us"})
    assert r.status_code == 201 and "PRIVATE KEY" not in r.text
    csr_id = r.json()["id"]
    dl = c.get(f"/api/settings/certificates/csr/{csr_id}/download")
    assert dl.headers["content-type"].startswith("application/pkcs10") and b"CERTIFICATE REQUEST" in dl.content
    wrong, _ = _leaf(pki["int"], pki["int_key"])  # signed for a different key
    assert c.post(f"/api/settings/certificates/csr/{csr_id}/complete",
                  files={"cert": ("c.pem", pem(wrong))}).status_code == 422
    signed = _sign_csr(dl.content, pki)
    r = c.post(f"/api/settings/certificates/csr/{csr_id}/complete",
               files={"cert": ("c.pem", pem(signed)), "chain": ("i.pem", pem(pki["int"]))})
    assert r.status_code == 200, r.text
    st = c.get("/api/settings/certificates").json()
    assert st["pending_csrs"] == [] and st["active"]["mode"] == "uploaded"
    assert c.post(f"/api/settings/certificates/csr/{csr_id}/complete",
                  files={"cert": ("c.pem", pem(signed))}).status_code == 422  # not pending any more


def test_csr_cancel_destroys_key(env):
    app, s, proxy, c = env
    csr_id = c.post("/api/settings/certificates/csr", json={"common_name": FQDN}).json()["id"]
    assert c.delete(f"/api/settings/certificates/csr/{csr_id}").status_code == 204
    from exposurecatalyst.models import TlsCsr

    with get_session_factory()() as db:
        row = db.get(TlsCsr, csr_id)
        assert row.status == "cancelled" and row.key_enc == ""


# ---- trusted CA (outbound) ---------------------------------------------------------------------------------

def test_trusted_ca_exports_combined_bundle(env, pki, monkeypatch):
    app, s, proxy, c = env
    for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "EXCAT_CA_BUNDLE"):
        monkeypatch.delenv(k, raising=False)
    tls._ca_state.update(mtime=None, exported=False)
    tls.apply_trusted_ca(s, force=True)
    bundle = os.environ["SSL_CERT_FILE"]
    data = Path(bundle).read_bytes()
    assert pem(pki["root"]) in data and data.count(b"BEGIN CERTIFICATE") > 100  # public roots + ours
    leaf, _ = _leaf(pki["int"], pki["int_key"])
    assert c.put("/api/settings/certificates/trusted-ca", files={"bundle": ("x.pem", pem(leaf))}).status_code == 422
    assert c.delete("/api/settings/certificates/trusted-ca").json() == {"certificates": []}
    assert "SSL_CERT_FILE" not in os.environ  # removed again: default trust exactly as before


# ---- ACME --------------------------------------------------------------------------------------------------

def test_acme_requires_its_flag(env):
    app, s, proxy, c = env
    r = c.put("/api/settings/certificates/acme", json={"enabled": True, "email": "pki@corp.example"})
    assert r.status_code == 403 and "features.acme" in r.text


def test_acme_renders_persists_and_reverts(monkeypatch, tmp_path):
    app, s, proxy = make(monkeypatch, tmp_path, acme=True)
    c = client(app)
    assert c.put("/api/settings/certificates/acme", json={"enabled": True}).status_code == 422  # email required
    r = c.put("/api/settings/certificates/acme", json={"enabled": True, "email": "pki@corp.example",
                                                       "challenge": "dns-01", "dns_provider": "cloudflare"})
    assert r.status_code == 200, r.text
    persisted = (s.certs_dir / "proxy" / "Caddyfile").read_text()
    assert f"{FQDN}:8443" in persisted and "dns cloudflare {env.EXCAT_ACME_CLOUDFLARE_API_TOKEN}" in persisted
    assert "email pki@corp.example" in persisted and proxy.loaded[-1] == persisted
    r = c.put("/api/settings/certificates/acme", json={"enabled": False})
    assert r.status_code == 200 and not (s.certs_dir / "proxy" / "Caddyfile").exists()
    assert "tls /certs/active/fullchain.pem" in proxy.loaded[-1]  # back to the default configuration


def test_acme_refuses_localhost(monkeypatch, tmp_path):
    s = Settings(env="test", database_url="sqlite://", fqdn="localhost", _env_file=None)
    with pytest.raises(tls.TlsError, match="public FQDN"):
        tls.render_acme_caddyfile(s, {"email": "a@b.co"})


# ---- expiry alerts -----------------------------------------------------------------------------------------

def test_expiry_alerts_once_per_threshold(env, pki):
    app, s, proxy, c = env
    leaf, key = _leaf(pki["int"], pki["int_key"], days=(-1, 40))
    assert c.post("/api/settings/certificates/install", files=files(leaf, key, [pki["int"]])).status_code == 200
    sent = []
    now = dt.datetime.now(dt.UTC)
    with get_session_factory()() as db:
        assert tls.expiry_alerts(db, s, now=now, send=lambda *a: sent.append(a[-1])) == []  # 40 days: nothing
        assert tls.expiry_alerts(db, s, now=now + dt.timedelta(days=11), send=lambda *a: sent.append(a[-1])) == [30]
        assert tls.expiry_alerts(db, s, now=now + dt.timedelta(days=12), send=lambda *a: sent.append(a[-1])) == []
        assert tls.expiry_alerts(db, s, now=now + dt.timedelta(days=34), send=lambda *a: sent.append(a[-1])) == [7]
    assert len(sent) == 2


# ---- migration 0008 ----------------------------------------------------------------------------------------

def test_migration_0008_upgrade_downgrade(tmp_path, monkeypatch):
    from alembic import command
    from sqlalchemy import create_engine, inspect

    from exposurecatalyst.cli import _alembic_config

    url = f"sqlite:///{tmp_path / 'mig.db'}"
    monkeypatch.setenv("EXCAT_DATABASE_URL", url)
    monkeypatch.setenv("EXCAT_ENV", "test")
    from exposurecatalyst.config import get_settings

    get_settings.cache_clear()  # migrations/env.py reads the cached settings
    monkeypatch.setattr("exposurecatalyst.config.get_settings", get_settings)
    cfg = _alembic_config()
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0008")
    tables = set(inspect(create_engine(url)).get_table_names())
    assert {"tls_certificates", "tls_csrs", "advisory_actions"} <= tables
    command.downgrade(cfg, "0007")
    tables = set(inspect(create_engine(url)).get_table_names())
    assert "tls_certificates" not in tables and "tls_csrs" not in tables and "advisory_actions" in tables
    command.upgrade(cfg, "head")
    get_settings.cache_clear()

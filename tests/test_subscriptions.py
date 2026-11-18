"""Phase 5: paid / licensed threat-intel & news subscriptions (features.subscriptions)."""

from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, date, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient

from exposurecatalyst.config import PROJECT_ROOT, Settings
from exposurecatalyst.db.base import Base
from exposurecatalyst.db.session import get_engine, get_session_factory
from exposurecatalyst.models import AuditLog, Cve, IntelItem, IntelSubscription, Role, User
from exposurecatalyst.security.passwords import hash_password
from exposurecatalyst.subscriptions import engine, jsonpath
from exposurecatalyst.subscriptions import service as svc

PW = "Correct-Horse-Battery-9"
CVE = "CVE-2026-1000"


def make(monkeypatch, *, subscriptions=True, **extra):
    s = Settings(env="test", database_url="sqlite://", cookie_secure=False, log_json=False, log_level="WARNING",
                 ssrf_resolve_dns=False, require_mfa_for_local_admins=False,
                 frontend_dist_dir=PROJECT_ROOT / "nonexistent", docs_site_dir=PROJECT_ROOT / "nonexistent",
                 features={"subscriptions": subscriptions}, **extra)
    import exposurecatalyst.api.auth as auth_mod
    import exposurecatalyst.main  # noqa: F401
    from exposurecatalyst.security import crypto

    for name, mod in list(sys.modules.items()):
        if name.startswith("exposurecatalyst") and hasattr(mod, "get_settings"):
            monkeypatch.setattr(mod, "get_settings", lambda: s)
    crypto.get_secret_box.cache_clear()
    auth_mod._limiter = None
    monkeypatch.setattr(svc, "TRANSPORTS", {})
    from exposurecatalyst.main import create_app
    from exposurecatalyst.security.rbac import seed_roles

    app = create_app(s)
    Base.metadata.create_all(get_engine())
    with get_session_factory()() as db:
        seed_roles(db)
        for name, role in (("root", "Super Admin"), ("ana", "Security Analyst"), ("vic", "Viewer")):
            db.add(User(username=name, password_hash=hash_password(PW), roles=[db.query(Role).filter_by(name=role).one()]))
        db.add(Cve(cve_id=CVE, title="Widget RCE", description="Remote code execution.", severity="CRITICAL",
                   cvss_score=9.8, cvss_version="3.1", provenance={}, cvss_metrics=[]))
        db.commit()
    return app, s


def client(app, user="root"):
    c = TestClient(app)
    c.__enter__()
    r = c.post("/api/auth/login", json={"username": user, "password": PW})
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


REST_CFG = {
    "auth": {"type": "bearer"},
    "endpoints": [{
        "name": "Vulns", "target": "cve", "path": "/v1/vulns", "params": {"since": "{since_iso}", "limit": "{limit}"},
        "results_path": "$.data[*]", "pagination": {"type": "cursor", "param": "cursor", "next_path": "$.meta.next"},
        "mapping": {"external_id": "$.id", "cve_id": "$.cve", "title": "$.name", "summary": "$.summary",
                    "description": "$.details", "severity": "$.score", "exploited": "$.exploitation",
                    "published": "$.updated", "references": "$.refs[*]", "url": "$.link", "tags": "$.tags"},
    }],
}


def rest_api(calls):
    def h(req: httpx.Request):
        calls.append(req)
        assert req.headers["authorization"] == "Bearer t0ken"
        if req.url.params.get("cursor") is None:
            return httpx.Response(200, json={"data": [
                {"id": "v1", "cve": CVE, "name": "Widget RCE exploited", "summary": "Actively exploited by FIN99.",
                 "details": "Long licensed analysis " * 20, "score": 9.6, "exploitation": "Active",
                 "updated": "2026-11-10T00:00:00Z", "refs": ["https://intel.example.com/r/1"],
                 "link": "https://intel.example.com/v1", "tags": ["ransomware"]},
                {"id": "v2", "name": "no cve here"}], "meta": {"next": "c2"}})
        return httpx.Response(200, json={"data": [{"id": "v3", "cve": "CVE-2026-2000", "name": "Other",
                                                   "score": "medium", "updated": 1762300800}], "meta": {}})
    return httpx.MockTransport(h)


def create_rest(c, **over):
    body = {"name": "Acme Intel", "preset": "custom_rest", "vendor": "Acme", "base_url": "https://intel.example.com",
            "enabled": True, "config": REST_CFG, "secrets": {"token": "t0ken"},
            "redistribution": {"email": "full", "ai": True, "default_tlp": "AMBER"}, **over}
    r = c.post("/api/subscriptions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


# ---- units -------------------------------------------------------------------------------------------------

def test_jsonpath_subset():
    doc = {"a": {"b": [{"c": 1}, {"c": 2}], "k.dot": "x"}, "list": [5, 6]}
    assert jsonpath.find(doc, "$.a.b[*].c") == [1, 2]
    assert jsonpath.first(doc, "a.b[1].c") == 2 and jsonpath.first(doc, "$.list[-1]") == 6
    assert jsonpath.first(doc, "$.a['k.dot']") == "x" and jsonpath.find(doc, "$.missing.x") == []
    for bad in ("", "$..c", "$.a[?(@.c>1)]", "$.a.b[1:2]"):
        with pytest.raises(jsonpath.PathError):
            jsonpath.parse(bad)


def test_value_coercion():
    assert engine.to_severity(9.8) == "CRITICAL" and engine.to_severity(72) == "HIGH"
    assert engine.to_severity("Very Critical") == "CRITICAL" and engine.to_severity("med") is None
    assert engine.to_bool("Active") is True and engine.to_bool("Not observed") is False
    assert engine.to_bool({"wild": True}) is True and engine.to_bool("maybe") is None
    assert engine.to_dt(1762300800).date() == date(2025, 11, 5) and engine.to_dt(1762300800000).year == 2025
    assert engine.to_dt("Tue, 10 Nov 2026 10:00:00 GMT").tzinfo is not None


def test_map_record_extracts_cves_and_constants():
    rec = engine.map_record({"t": "Exploit for cve-2026-1234 and CVE-2026-5678", "id": 7},
                            {"title": "$.t", "external_id": "$.id", "exploited": "=true"}, "cve")
    assert rec.cve_ids == ["CVE-2026-1234", "CVE-2026-5678"] and rec.exploited is True and rec.external_id == "7"
    assert engine.map_record({"t": "no ids"}, {"title": "$.t"}, "cve") is None  # CVE targets need a CVE
    assert engine.map_record({"t": "news"}, {"title": "$.t"}, "news").kind == "news"


def test_stix_mapping():
    recs, skipped = engine.stix_records([
        {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2026-1000",
         "external_references": [{"source_name": "cve", "external_id": "CVE-2026-1000"},
                                 {"source_name": "vendor", "url": "https://v.example.com/a"}]},
        {"type": "report", "id": "report--1", "name": "Campaign hits CVE-2026-1000", "description": "d",
         "published": "2026-11-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--1"}])
    assert [r.kind for r in recs] == ["cve", "news"] and skipped == 1
    assert recs[0].references == ["https://v.example.com/a"] and recs[1].cve_ids == ["CVE-2026-1000"]


# ---- flags & RBAC ------------------------------------------------------------------------------------------

def test_flag_off_hides_everything(monkeypatch):
    app, s = make(monkeypatch, subscriptions=False)
    c = client(app)
    assert c.get("/api/subscriptions/status").json() == {"enabled": False}
    for method, path in (("get", "/api/subscriptions"), ("get", "/api/subscriptions/presets"),
                         ("get", "/api/subscriptions/intel"), ("post", "/api/subscriptions/preview")):
        assert getattr(c, method)(path, **({"json": {}} if method == "post" else {})).status_code == 403, path


def test_rbac(monkeypatch):
    app, _ = make(monkeypatch)
    ana, vic = client(app, "ana"), client(app, "vic")
    assert ana.post("/api/subscriptions", json={"name": "x", "preset": "manual"}).status_code == 403
    assert vic.get("/api/subscriptions").status_code == 403
    assert vic.get("/api/subscriptions/intel").status_code == 200
    assert vic.post("/api/subscriptions/intel", json={"subscription_id": 1}).status_code == 403


# ---- configuration, preview, sync ---------------------------------------------------------------------------

def test_presets_catalog_covers_spec(monkeypatch):
    app, _ = make(monkeypatch)
    keys = {p["key"] for p in client(app).get("/api/subscriptions/presets").json()}
    assert {"recorded_future", "google_ti_mandiant", "vulncheck", "flashpoint", "intel471", "crowdstrike_intel",
            "msft_defender_ti", "cyware", "threatconnect", "anomali", "feedly", "silobreaker", "dataminr",
            "socradar", "cybersixgill", "reliaquest_greymatter", "securin"} <= keys
    assert {"custom_rest", "custom_rss", "custom_taxii", "manual"} <= keys


def test_preview_before_save_and_secrets_never_returned(monkeypatch):
    app, s = make(monkeypatch)
    calls = []
    svc.TRANSPORTS["custom_rest"] = rest_api(calls)
    c = client(app)
    r = c.post("/api/subscriptions/preview", json={"preset": "custom_rest", "base_url": "https://intel.example.com",
                                                   "config": REST_CFG, "secrets": {"token": "t0ken"}}).json()
    assert r["ok"] and [x["cve_ids"] for x in r["records"]] == [[CVE]] and r["skipped"] == 1
    assert '"cve": "CVE-2026-1000"' in r["raw_sample"]
    with get_session_factory()() as db:
        assert db.query(IntelSubscription).count() == 0  # nothing saved
    sub = create_rest(c)
    assert sub["secrets_set"] == ["token"] and "t0ken" not in json.dumps(sub)
    assert "t0ken" not in c.get("/api/subscriptions").text
    with get_session_factory()() as db:
        assert "t0ken" not in json.dumps([a.details for a in db.query(AuditLog).all()])


def test_sync_upserts_paginates_and_tracks_usage(monkeypatch):
    app, s = make(monkeypatch)
    calls = []
    svc.TRANSPORTS["custom_rest"] = rest_api(calls)
    c = client(app)
    sub = create_rest(c)
    r = c.post(f"/api/subscriptions/{sub['id']}/sync").json()
    assert r == {"ok": True, "created": 2, "updated": 0, "skipped": 1, "calls": 2}
    assert calls[1].url.params["cursor"] == "c2"
    r = c.post(f"/api/subscriptions/{sub['id']}/sync").json()
    assert r["created"] == 0 and r["updated"] == 2  # upsert, no duplicates
    st = next(x for x in c.get("/api/subscriptions").json() if x["id"] == sub["id"])
    assert st["usage"]["api_calls"] == 4 and st["items"] == 2 and st["status"] == "ok"
    with get_session_factory()() as db:
        item = db.query(IntelItem).filter_by(external_id="v1").one()
        assert item.severity == "CRITICAL" and item.exploited is True and item.tlp == "AMBER"
        assert db.query(IntelItem).filter_by(external_id="v3").one().severity == "MEDIUM"
    # incremental window starts from the newest stored item
    assert "2026-11-09T23:00:00Z" in str(calls[-1].url) or "2026-11-09T23" in calls[2].url.params.get("since", "")


def test_quota_exhaustion_skips_sync(monkeypatch):
    app, _ = make(monkeypatch)
    svc.TRANSPORTS["custom_rest"] = rest_api([])
    c = client(app)
    sub = create_rest(c, license={"api_quota": 2, "quota_period": "month"})
    assert c.post(f"/api/subscriptions/{sub['id']}/sync").json()["ok"]
    r = c.post(f"/api/subscriptions/{sub['id']}/sync").json()
    assert not r["ok"] and "quota" in r["error"]
    st = next(x for x in c.get("/api/subscriptions").json() if x["id"] == sub["id"])
    assert st["quota_left"] == 0 and st["error_log"][0]["error"].startswith("API quota")


def test_oauth2_preset_mandiant(monkeypatch):
    app, _ = make(monkeypatch)
    seen = {}

    def h(req):
        if req.url.path == "/token":
            seen["basic"] = req.headers["authorization"]
            assert parse_qs(req.content.decode())["grant_type"] == ["client_credentials"]
            return httpx.Response(200, json={"access_token": "mt", "expires_in": 3600})
        assert req.headers["authorization"] == "Bearer mt" and req.headers["x-app-name"] == "ExposureCatalyst"
        if "next" not in req.url.params:
            return httpx.Response(200, json={"vulnerability": [
                {"id": "vulnerability--x", "cve_id": CVE, "title": "Widget RCE", "risk_rating": "CRITICAL",
                 "exploitation_state": "Wide", "publish_date": "2026-11-01T00:00:00Z",
                 "sources": [{"url": "https://m.example.com"}]}], "next": "n2"})
        return httpx.Response(200, json={"vulnerability": []})

    svc.TRANSPORTS["google_ti_mandiant"] = httpx.MockTransport(h)
    c = client(app)
    sub = c.post("/api/subscriptions", json={"name": "Mandiant", "preset": "google_ti_mandiant", "enabled": True,
                                             "secrets": {"client_id": "kid", "client_secret": "ksec"}}).json()
    assert sub["base_url"] == "https://api.intelligence.mandiant.com" and sub["api_status"] == "documented"
    assert c.post(f"/api/subscriptions/{sub['id']}/sync").json()["created"] == 1
    assert seen["basic"] == "Basic " + base64.b64encode(b"kid:ksec").decode()


def test_vulncheck_cursor_drops_start_param(monkeypatch):
    app, _ = make(monkeypatch)
    reqs = []

    def h(req):
        reqs.append(req)
        if "cursor" not in req.url.params:
            assert req.url.params["start_cursor"] == "true"
            return httpx.Response(200, json={"_meta": {"next_cursor": "abc"}, "data": [
                {"cve": [CVE], "vulnerabilityName": "Widget RCE", "shortDescription": "x", "date_added": "2026-11-02"}]})
        assert "start_cursor" not in req.url.params
        return httpx.Response(200, json={"_meta": {}, "data": []})

    svc.TRANSPORTS["vulncheck"] = httpx.MockTransport(h)
    c = client(app)
    sub = c.post("/api/subscriptions", json={"name": "VulnCheck", "preset": "vulncheck", "enabled": True,
                                             "secrets": {"token": "vc"}}).json()
    assert c.post(f"/api/subscriptions/{sub['id']}/sync").json()["created"] == 1
    with get_session_factory()() as db:
        assert db.query(IntelItem).one().exploited is True  # KEV constant mapping


def test_rss_and_taxii(monkeypatch):
    app, _ = make(monkeypatch)
    rss = (b"<?xml version='1.0'?><rss><channel><item><title>FIN99 exploits CVE-2026-1000</title>"
           b"<link>https://news.example.com/a</link><description>Licensed note</description>"
           b"<pubDate>Tue, 10 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>")

    def rss_h(req):
        assert req.headers["x-api-key"] == "rk"
        return httpx.Response(200, content=rss, headers={"content-type": "application/rss+xml"})

    pages = []

    def taxii_h(req):
        pages.append(req)
        assert req.headers["accept"].startswith("application/taxii+json;version=2.1")
        assert req.url.path == "/api1/collections/coll-1/objects/"
        if "next" not in req.url.params:
            return httpx.Response(200, json={"more": True, "next": "p2", "objects": [
                {"type": "vulnerability", "id": "vulnerability--1", "name": CVE,
                 "external_references": [{"source_name": "cve", "external_id": CVE}]}]})
        assert req.url.params["added_after"]  # filters kept on later pages
        return httpx.Response(200, json={"more": False, "objects": [
            {"type": "report", "id": "report--2", "name": "Campaign report", "published": "2026-11-03T00:00:00Z"}]})

    svc.TRANSPORTS.update({"custom_rss": httpx.MockTransport(rss_h), "custom_taxii": httpx.MockTransport(taxii_h)})
    c = client(app)
    r = c.post("/api/subscriptions", json={"name": "Feed", "preset": "custom_rss", "enabled": True,
                                           "base_url": "https://news.example.com/feed.xml",
                                           "config": {"auth": {"type": "api_key_header", "header": "X-API-Key"}},
                                           "secrets": {"api_key": "rk"}}).json()
    assert c.post(f"/api/subscriptions/{r['id']}/sync").json()["created"] == 1
    t = c.post("/api/subscriptions", json={"name": "TAXII", "preset": "custom_taxii", "enabled": True,
                                           "base_url": "https://taxii.example.com/api1/",
                                           "config": {"collection_id": "coll-1"},
                                           "secrets": {"username": "u", "password": "p"}}).json()
    assert c.post(f"/api/subscriptions/{t['id']}/sync").json()["created"] == 2 and len(pages) == 2
    news = client(app, "vic").get("/api/subscriptions/intel", params={"kind": "news"}).json()
    assert {n["title"] for n in news} >= {"FIN99 exploits CVE-2026-1000", "Campaign report"}
    assert all(n["source"].startswith("Custom") for n in news)  # attribution on every item


# ---- SSRF --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://intel.example.com", "https://169.254.169.254/", "https://10.0.0.5/api",
                                 "https://intel.example.com/#frag"])
def test_custom_url_ssrf_rejected(monkeypatch, url):
    app, _ = make(monkeypatch)
    r = client(app).post("/api/subscriptions", json={"name": "Bad", "preset": "custom_rest", "base_url": url,
                                                     "config": REST_CFG})
    assert r.status_code == 422 and "Base URL rejected" in r.text


def test_preset_host_pinned_and_pagination_host_checked(monkeypatch):
    app, _ = make(monkeypatch)
    c = client(app)
    r = c.post("/api/subscriptions", json={"name": "RF", "preset": "recorded_future", "base_url": "https://evil.example.com"})
    assert r.status_code == 422 and "not a Recorded Future host" in r.text
    cfg = json.loads(json.dumps(REST_CFG))
    cfg["endpoints"][0]["pagination"] = {"type": "next_url", "next_path": "$.meta.next"}
    svc.TRANSPORTS["custom_rest"] = httpx.MockTransport(lambda req: httpx.Response(200, json={
        "data": [{"id": "v1", "cve": CVE, "name": "x"}], "meta": {"next": "https://attacker.example.net/steal"}}))
    sub = create_rest(c, config=cfg)
    r = c.post(f"/api/subscriptions/{sub['id']}/sync").json()
    assert not r["ok"] and "not allowed" in r["error"]


def test_config_validation(monkeypatch):
    app, _ = make(monkeypatch)
    c = client(app)
    bad = [{"auth": {"type": "kerberos"}}, {"endpoints": [{"method": "POST"}]},
           {"endpoints": [{"path": "https://other.example.com/x"}]},
           {"endpoints": [{"mapping": {"title": "$..x"}}]}, {"poll_minutes": 1}, {"nope": 1}]
    for cfg in bad:
        r = c.post("/api/subscriptions", json={"name": "B", "preset": "custom_rest",
                                               "base_url": "https://intel.example.com", "config": cfg})
        assert r.status_code == 422, cfg
    r = c.post("/api/subscriptions", json={"name": "B", "preset": "manual", "license": {"renewal_date": "soon"}})
    assert r.status_code == 422


# ---- redistribution enforcement ------------------------------------------------------------------------------

def _seed_items(db, policy_full, policy_none, ai_allowed, ai_denied):
    def sub(name, email, ai):
        s = IntelSubscription(name=name, vendor=name, preset="manual", source_type="manual", enabled=True, config={},
                              license={}, redistribution={"email": email, "ai": ai, "default_tlp": "AMBER"},
                              error_log=[], usage={}, state={})
        db.add(s)
        db.flush()
        return s

    a, b = sub("FullVendor", policy_full, ai_allowed), sub("NoneVendor", policy_none, ai_denied)
    db.add_all([
        IntelItem(subscription=a, kind="cve", external_id="a1", cve_ids=[CVE], title="Full item",
                  summary="Full summary", description="Full description", tlp="AMBER", is_manual=False, tags=[],
                  references=[]),
        IntelItem(subscription=a, kind="cve", external_id="a2", cve_ids=[CVE], title="Red item", summary="secret",
                  tlp="RED", is_manual=False, tags=[], references=[]),
        IntelItem(subscription=b, kind="cve", external_id="b1", cve_ids=[CVE], title="None item",
                  summary="Not for email", tlp="GREEN", is_manual=False, tags=[], references=[]),
    ])
    db.commit()


def test_email_and_ai_enforce_licence(monkeypatch):
    app, s = make(monkeypatch)
    with get_session_factory()() as db:
        _seed_items(db, "full", "none", True, False)
        intel = svc.email_intel(db, CVE)
        assert [i["title"] for i in intel] == ["Full item"]  # RED and email=none excluded
        assert intel[0]["description"] == "Full description"
        sub = db.query(IntelSubscription).filter_by(name="FullVendor").one()
        sub.redistribution = {**sub.redistribution, "email": "summary"}
        db.commit()
        assert "description" not in svc.email_intel(db, CVE)[0]  # summary only
        text = svc.ai_intel_text(db, CVE)
        assert "Full item" in text and "None item" not in text and "secret" not in text


def test_advisory_email_section_only_with_flag(monkeypatch):
    for flag in (False, True):
        app, s = make(monkeypatch, subscriptions=flag)
        with get_session_factory()() as db:
            _seed_items(db, "full", "none", True, False)
        ana = client(app, "ana")
        adv = ana.post("/api/advisories", json={"cve_id": CVE})
        assert adv.status_code == 201, adv.text
        html = ana.get(f"/api/advisories/{adv.json()['id']}/preview").text
        assert ("Threat intelligence (licensed sources)" in html) is flag
        assert "Not for email" not in html and "secret" not in html
        if flag:
            assert "FullVendor · FullVendor" in html and "TLP:AMBER" in html


def test_ai_context_includes_only_permitted(monkeypatch):
    app, s = make(monkeypatch)
    from exposurecatalyst.ai import service as ai

    with get_session_factory()() as db:
        _seed_items(db, "full", "none", True, False)
        cve = db.query(Cve).filter_by(cve_id=CVE).one()

        class R:
            def known(self, *a):
                pass

        _, text = ai.cve_context(db, cve, R())
        assert "Licensed threat intelligence" in text and "Full item" in text
        assert "None item" not in text and "Red item" not in text
    app2, _ = make(monkeypatch, subscriptions=False)
    with get_session_factory()() as db:
        _seed_items(db, "full", "none", True, False)
        _, text = ai.cve_context(db, db.query(Cve).filter_by(cve_id=CVE).one(), R())
        assert "Licensed threat intelligence" not in text  # flag off = unchanged


def test_tlp_red_visible_only_with_intel_manage(monkeypatch):
    app, _ = make(monkeypatch)
    with get_session_factory()() as db:
        _seed_items(db, "full", "none", True, False)
    titles = lambda u: {i["title"] for i in client(app, u).get("/api/subscriptions/intel", params={"cve_id": CVE}).json()}  # noqa: E731
    assert "Red item" not in titles("vic") and "Red item" in titles("ana")


# ---- manual entry, attachments, import -----------------------------------------------------------------------

def test_manual_item_attachments_and_labels(monkeypatch):
    app, _ = make(monkeypatch)
    root, ana = client(app), client(app, "ana")
    sub = root.post("/api/subscriptions", json={"name": "Portal X", "preset": "manual"}).json()
    r = ana.post("/api/subscriptions/intel", json={"subscription_id": sub["id"], "kind": "cve", "cve_ids": [CVE],
                                                   "title": "From the vendor portal", "summary": "PDF brief",
                                                   "tlp": "TLP:GREEN", "analyst_notes": "call vendor"})
    assert r.status_code == 201, r.text
    item = r.json()
    assert item["source"] == "Manual — Portal X" and item["tlp"] == "GREEN" and item["is_manual"]
    pdf = b"%PDF-1.7\n%test\n"
    a = ana.post(f"/api/subscriptions/intel/{item['id']}/attachments", files={"file": ("brief.pdf", pdf)})
    assert a.status_code == 201
    assert ana.post(f"/api/subscriptions/intel/{item['id']}/attachments",
                    files={"file": ("x.exe", b"MZ\x90")}).status_code == 422
    dl = client(app, "vic").get(f"/api/subscriptions/attachments/{a.json()['id']}")
    assert dl.content == pdf and dl.headers["content-disposition"].startswith("attachment")
    assert "sandbox" in dl.headers["content-security-policy"]
    assert ana.post("/api/subscriptions/intel", json={"subscription_id": sub["id"], "kind": "cve",
                                                      "title": "no cve"}).status_code == 422


def test_import_csv_json_stix(monkeypatch):
    app, _ = make(monkeypatch)
    root, ana = client(app), client(app, "ana")
    sub = root.post("/api/subscriptions", json={"name": "Imports", "preset": "manual"}).json()
    csv_data = ("kind,cve_ids,title,summary,tlp,severity,exploited\n"
                f"cve,{CVE},Imported A,s,GREEN,high,yes\n"
                "cve,,Missing CVE,s,GREEN,,\n"
                "news,,Imported news,s,PURPLE,,\n").encode()
    pv = ana.post("/api/subscriptions/import/preview", data={"subscription_id": sub["id"]},
                  files={"file": ("x.csv", csv_data)}).json()
    assert pv["valid"] == 1 and pv["error_count"] == 2 and pv["sample"][0]["severity"] == "HIGH"
    assert ana.post("/api/subscriptions/import", data={"subscription_id": sub["id"]},
                    files={"file": ("x.csv", csv_data)}).status_code == 422
    r = ana.post("/api/subscriptions/import", data={"subscription_id": sub["id"], "skip_invalid": "true"},
                 files={"file": ("x.csv", csv_data)}).json()
    assert r == {"imported": 1, "skipped_invalid": 2, "format": "csv"}
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "vulnerability", "id": "vulnerability--9", "name": CVE,
         "external_references": [{"source_name": "cve", "external_id": CVE}]},
        {"type": "malware", "id": "malware--1"}]}
    r = ana.post("/api/subscriptions/import", data={"subscription_id": sub["id"]},
                 files={"file": ("b.json", json.dumps(bundle).encode())}).json()
    assert r["imported"] == 1 and r["format"].startswith("stix")
    r = ana.post("/api/subscriptions/import", data={"subscription_id": sub["id"]},
                 files={"file": ("l.json", json.dumps([{"title": "Plain news"}]).encode())}).json()
    assert r["imported"] == 1
    with get_session_factory()() as db:
        assert db.query(IntelItem).filter_by(is_manual=True).count() == 3
        assert db.query(AuditLog).filter_by(action="intel.imported").count() == 3


# ---- licence -----------------------------------------------------------------------------------------------

def test_renewal_reminders_60_30_7(monkeypatch):
    app, s = make(monkeypatch)
    c = client(app)
    today = datetime.now(UTC)
    c.post("/api/subscriptions", json={"name": "Lic", "preset": "manual", "license": {
        "contract_owner": "cti@corp.example", "license_tier": "Enterprise", "seats": 5, "api_quota": 10000,
        "renewal_date": (today + timedelta(days=70)).date().isoformat(), "cost_center": "SEC-01"}})
    sent = []
    with get_session_factory()() as db:
        for days, expect in ((0, []), (11, ["Lic:60"]), (12, []), (41, ["Lic:30"]), (64, ["Lic:7"])):
            got = svc.renewal_reminders(db, s, now=today + timedelta(days=days), send=lambda *a: sent.append(a[-1]))
            assert got == expect, (days, got)
    assert len(sent) == 3


# ---- migration 0009 ----------------------------------------------------------------------------------------

def test_migration_0009_upgrade_downgrade(tmp_path, monkeypatch):
    from alembic import command
    from sqlalchemy import create_engine, inspect

    from exposurecatalyst.cli import _alembic_config

    url = f"sqlite:///{tmp_path / 'm.db'}"
    monkeypatch.setenv("EXCAT_DATABASE_URL", url)
    monkeypatch.setenv("EXCAT_ENV", "test")
    from exposurecatalyst.config import get_settings

    get_settings.cache_clear()  # migrations/env.py reads the cached settings
    monkeypatch.setattr("exposurecatalyst.config.get_settings", get_settings)
    cfg = _alembic_config()
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    assert {"intel_subscriptions", "intel_items", "intel_attachments"} <= set(inspect(create_engine(url)).get_table_names())
    command.downgrade(cfg, "0008")
    t = set(inspect(create_engine(url)).get_table_names())
    assert not {"intel_subscriptions", "intel_items", "intel_attachments"} & t and "tls_certificates" in t
    command.upgrade(cfg, "head")
    get_settings.cache_clear()

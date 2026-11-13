from __future__ import annotations

from datetime import UTC, datetime

import pytest

from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.help import filter_body
from exposurecatalyst.models import Cve, CveProduct
from exposurecatalyst.security.ssrf import UnsafeURLError, validate_outbound_url


@pytest.fixture
def seeded(app):
    with get_session_factory()() as s:
        s.add_all([
            Cve(cve_id="CVE-2024-21762", title="FortiOS OOB write", description="out-of-bounds write", severity="CRITICAL",
                cvss_score=9.8, epss_score=0.94, kev=True, exploit_available=True, provenance={}, cvss_metrics=[],
                published_at=datetime(2024, 2, 9, tzinfo=UTC), last_modified_at=datetime(2024, 3, 1, tzinfo=UTC),
                products=[CveProduct(vendor="fortinet", product="fortios", source="nvd")]),
            Cve(cve_id="CVE-2024-0001", title="Widget XSS 100%_done", description="xss", severity="MEDIUM",
                cvss_score=6.1, epss_score=0.01, provenance={}, cvss_metrics=[],
                published_at=datetime(2024, 2, 10, tzinfo=UTC), last_modified_at=datetime(2024, 2, 11, tzinfo=UTC),
                products=[CveProduct(vendor="example", product="widget", source="nvd")]),
            Cve(cve_id="CVE-2024-0002", title="No score yet", severity="UNKNOWN", provenance={}, cvss_metrics=[]),
        ])
        s.commit()


@pytest.mark.parametrize("params,expected", [
    ({}, ["CVE-2024-21762", "CVE-2024-0001", "CVE-2024-0002"]),
    ({"q": "cve-2024-21762"}, ["CVE-2024-21762"]),
    ({"q": "100%_"}, ["CVE-2024-0001"]),  # LIKE wildcards escaped
    ({"q": "1_0"}, []),  # "_" is literal, not a single-char wildcard (would match "100")
    ({"vendor": "forti"}, ["CVE-2024-21762"]),
    ({"severity": ["critical", "MEDIUM"]}, ["CVE-2024-21762", "CVE-2024-0001"]),
    ({"cvss_min": 7}, ["CVE-2024-21762"]),
    ({"epss_min": 0.5}, ["CVE-2024-21762"]),
    ({"kev": "true"}, ["CVE-2024-21762"]),
    ({"exploit": "false"}, ["CVE-2024-0001", "CVE-2024-0002"]),
    ({"published_from": "2024-02-10"}, ["CVE-2024-0001"]),
    ({"sort": "cvss_score"}, ["CVE-2024-0001", "CVE-2024-21762", "CVE-2024-0002"]),  # NULLs last
])
def test_search_filters(login, seeded, params, expected):
    r = login("Viewer").get("/api/cves", params=params)
    assert r.status_code == 200, r.text
    assert [i["cve_id"] for i in r.json()["items"]] == expected


def test_search_rejects_bad_sort_and_paginates(login, seeded):
    c = login("Viewer")
    assert c.get("/api/cves", params={"sort": "password_hash"}).status_code == 422
    r = c.get("/api/cves", params={"page_size": 1, "page": 2}).json()
    assert r["total"] == 3 and len(r["items"]) == 1


def test_cve_detail_and_assets_empty_state(login, seeded):
    c = login("Viewer")
    d = c.get("/api/cves/cve-2024-21762").json()
    assert d["vendors"] == ["fortinet"] and d["products"][0]["product"] == "fortios"
    assert c.get("/api/cves/CVE-2099-9999").status_code == 404
    assert c.get("/api/cves/not-a-cve").status_code == 422
    assets = c.get("/api/cves/CVE-2024-21762/assets").json()
    assert assets["integrations_configured"] is False and "Settings" in assets["message"]


def test_saved_searches_are_per_user(login, seeded):
    a, b = login("Viewer", username="ann"), login("Viewer", username="ben")
    r = a.post("/api/saved-searches", json={"name": "KEV crit", "query": {"kev": True, "severity": ["CRITICAL"]}})
    assert r.status_code == 201
    sid = r.json()["id"]
    assert a.post("/api/saved-searches", json={"name": "KEV crit", "query": {}}).status_code == 409
    assert a.post("/api/saved-searches", json={"name": "x", "query": {"evil": 1}}).status_code == 422
    assert b.get("/api/saved-searches").json() == []
    assert b.delete(f"/api/saved-searches/{sid}").status_code == 404  # no IDOR
    assert a.delete(f"/api/saved-searches/{sid}").status_code == 204


def test_sources_health_and_refresh(login):
    c = login("Security Analyst")
    body = c.get("/api/sources").json()
    assert [s["source"] for s in body["sources"]] == ["nvd", "kev", "epss", "news"]
    assert body["scheduler_alive"] is False
    assert all(s["health"] == "pending" for s in body["sources"])
    assert c.post("/api/sources/refresh", params={"source": "kev"}).json()["queued"] == ["kev"]
    assert c.get("/api/sources").json()["sources"][1]["refresh_pending"] is True
    assert c.post("/api/sources/refresh", params={"source": "bogus"}).status_code == 422


# --- help ----------------------------------------------------------------------------------------

def test_filter_body_strips_blocks_without_permission():
    body = "Intro\n<!-- requires: source:manage -->\nAdmin step\n<!-- /requires -->\nOutro"
    assert "Admin step" not in filter_body(body, {"cve:view"})
    assert "Admin step" in filter_body(body, {"source:manage"})


def test_help_api_respects_rbac(login):
    viewer, admin = login("Viewer"), login("Super Admin")
    v_ids = {h["id"] for h in viewer.get("/api/help").json()}
    a_ids = {h["id"] for h in admin.get("/api/help").json()}
    assert "cve-intelligence" in v_ids and "settings-rbac" not in v_ids and "settings-rbac" in a_ids
    assert viewer.get("/api/help/pages/settings-rbac").status_code == 404
    v_page = viewer.get("/api/help/pages/cve-intelligence").json()["markdown"]
    a_page = admin.get("/api/help/pages/cve-intelligence").json()["markdown"]
    assert "Settings → Sources" not in v_page and "Settings → Sources" in a_page
    assert viewer.get("/api/help/search", params={"q": "EPSS"}).json()
    tips = viewer.get("/api/help/tooltips").json()
    assert {"cvss", "epss", "kev"} <= tips.keys()


# --- SSRF ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://169.254.169.254/latest/meta-data/",
    "https://127.0.0.1/",
    "https://10.0.0.5/",
    "https://[::1]/",
    "https://[::ffff:169.254.169.254]/",
    "https://100.64.0.1/",
    "http://services.nvd.nist.gov/",
    "https://user:pw@services.nvd.nist.gov/",
    "file:///etc/passwd",
    "https://metadata.google.internal/",
])
def test_ssrf_blocked(url):
    with pytest.raises(UnsafeURLError):
        validate_outbound_url(url, allowlist=None, resolve_dns=False)


def test_ssrf_allowlist_matching():
    allow = ["services.nvd.nist.gov", "*.qualys.com"]
    assert validate_outbound_url("https://services.nvd.nist.gov/x", allowlist=allow, resolve_dns=False)
    assert validate_outbound_url("https://qualysapi.qualys.com/x", allowlist=allow, resolve_dns=False)
    for bad in ("https://qualys.com/", "https://services.nvd.nist.gov.evil.com/", "https://evilqualys.com/"):
        with pytest.raises(UnsafeURLError):
            validate_outbound_url(bad, allowlist=allow, resolve_dns=False)
    assert validate_outbound_url("https://10.0.0.5/", allowlist=None, allow_private=True, resolve_dns=False)

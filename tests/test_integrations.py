from __future__ import annotations

import json

import httpx
import pytest

from exposurecatalyst.connectors import service as corr
from exposurecatalyst.connectors.base import get_path, map_record
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import Cve, CveProduct, Integration

CVE = "CVE-2024-21762"

QUALYS_ABOUT = b"<?xml version='1.0'?><ABOUT><API-VERSION>2.0</API-VERSION><WEB-VERSION>10.30</WEB-VERSION></ABOUT>"
QUALYS_KB = f"""<?xml version="1.0"?><KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><VULN_LIST>
<VULN><QID>38170</QID><CVE_LIST><CVE><ID>{CVE}</ID></CVE></CVE_LIST></VULN>
<VULN><QID>99999</QID><CVE_LIST><CVE><ID>CVE-2020-0001</ID></CVE></CVE_LIST></VULN>
</VULN_LIST></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>""".encode()


def qualys_detections(page: int) -> bytes:
    host = ("<HOST><ID>1</ID><IP>10.0.0.5</IP><DNS>web01.corp</DNS><OS>RHEL 9</OS><DETECTION_LIST><DETECTION>"
            "<QID>38170</QID><STATUS>Active</STATUS><FIRST_FOUND_DATETIME>2026-11-01T10:00:00Z</FIRST_FOUND_DATETIME>"
            "</DETECTION></DETECTION_LIST></HOST>") if page == 1 else (
            "<HOST><ID>2</ID><IP>10.0.0.9</IP><DNS_DATA><HOSTNAME>app02</HOSTNAME></DNS_DATA><DETECTION_LIST>"
            "<DETECTION><QID>38170</QID><STATUS>New</STATUS></DETECTION></DETECTION_LIST></HOST>")
    warning = ("<WARNING><CODE>1980</CODE><URL>https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/asset/host/vm/"
               "detection/?action=list&amp;id_min=2</URL></WARNING>") if page == 1 else ""
    return (f"<?xml version='1.0'?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>{host}</HOST_LIST>{warning}"
            f"</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>").encode()


class Calls:
    def __init__(self):
        self.log = []


def qualys_transport(calls: Calls, evil_link: bool = False):
    def h(req: httpx.Request):
        calls.log.append(str(req.url))
        assert req.headers["X-Requested-With"] == "ExposureCatalyst" and req.headers["Authorization"].startswith("Basic ")
        p = req.url.path
        if p == "/msp/about.php":
            return httpx.Response(200, content=QUALYS_ABOUT)
        if p.endswith("knowledge_base/vuln/"):
            return httpx.Response(200, content=QUALYS_KB)
        if p.endswith("host/vm/detection/"):
            if evil_link:
                return httpx.Response(200, content=qualys_detections(1).replace(b"qualysapi.qg2.apps.qualys.com", b"evil.example"))
            assert req.url.params.get("qids") in (None, "38170")
            return httpx.Response(200, content=qualys_detections(2 if "id_min" in str(req.url) else 1))
        return httpx.Response(404)
    return httpx.MockTransport(h)


def wiz_transport(calls: Calls):
    def h(req: httpx.Request):
        calls.log.append(req.url.host)
        if req.url.host == "auth.app.wiz.io":
            assert b"grant_type=client_credentials" in req.content and b"audience=wiz-api" in req.content
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        assert req.headers["Authorization"] == "Bearer tok"
        body = json.loads(req.content)
        if "ExcatVulnFindings" not in body["query"]:
            return httpx.Response(200, json={"data": {"vulnerabilityFindings": {"nodes": []}}})
        assert body["variables"]["filterBy"]["vulnerabilityExternalId"] == [CVE]
        if body["variables"]["after"] is None:
            nodes = [{"id": "wf-1", "firstDetectedAt": "2026-11-02T00:00:00Z", "vulnerableAsset": {
                "name": "WEB01.corp", "ipAddresses": ["10.0.0.5"], "providerUniqueId": "i-0abc",
                "subscriptionExternalId": "123456789012", "operatingSystem": "Linux"}}]
            return httpx.Response(200, json={"data": {"vulnerabilityFindings": {
                "nodes": nodes, "pageInfo": {"hasNextPage": True, "endCursor": "c1"}}}})
        return httpx.Response(200, json={"data": {"vulnerabilityFindings": {"nodes": [
            {"id": "wf-2", "vulnerableAsset": {"name": "lambda-x", "providerUniqueId": "arn:aws:lambda:x"}}],
            "pageInfo": {"hasNextPage": False, "endCursor": None}}}})
    return httpx.MockTransport(h)


def tanium_transport(calls: Calls, fail: bool = False):
    def h(req):
        calls.log.append(req.url.path)
        assert req.headers["session"] == "tan-token"
        if fail:
            return httpx.Response(503)
        return httpx.Response(200, json={"data": {"endpoints": {"edges": [], "pageInfo": {"hasNextPage": False}}}})
    return httpx.MockTransport(h)


def snow_transport(calls: Calls):
    def h(req):
        calls.log.append(str(req.url))
        q = req.url.params.get("sysparm_query", "")
        if req.url.path.endswith("/sn_vul_vulnerable_item"):
            assert q == f"vulnerability.id={CVE}^active=true"
            return httpx.Response(200, headers={"X-Total-Count": "1"}, json={"result": [{
                "number": "VIT0001", "first_found": "2026-10-30 08:00:00", "cmdb_ci.name": "db03",
                "cmdb_ci.ip_address": "10.0.3.3", "cmdb_ci.owned_by": "Dana DBA", "cmdb_ci.department": "Finance",
                "cmdb_ci.used_for": "Production"}]})
        if req.url.path.endswith("/cmdb_ci_computer"):
            if "web01" in q or "10.0.0.5" in q:
                return httpx.Response(200, json={"result": [{"name": "web01", "owned_by": "Web Team",
                                                            "department": "Digital", "used_for": "Production"}]})
            return httpx.Response(200, json={"result": []})
        return httpx.Response(404)
    return httpx.MockTransport(h)


@pytest.fixture
def admin(login):
    return login("Admin", username="intadmin")


@pytest.fixture
def cve(app):
    with get_session_factory()() as s:
        s.add(Cve(cve_id=CVE, title="FortiOS", severity="CRITICAL", cvss_score=9.8, kev=True, provenance={},
                  cvss_metrics=[], products=[CveProduct(vendor="fortinet", product="fortios", source="nvd")]))
        s.commit()


@pytest.fixture
def transports(monkeypatch):
    calls = {k: Calls() for k in ("qualys", "wiz", "tanium", "servicenow_cmdb")}
    t = {"qualys": qualys_transport(calls["qualys"]), "wiz": wiz_transport(calls["wiz"]),
         "tanium": tanium_transport(calls["tanium"]), "servicenow_cmdb": snow_transport(calls["servicenow_cmdb"])}
    monkeypatch.setattr(corr, "TRANSPORTS", t)
    return calls


def _create(c, **body):
    r = c.post("/api/integrations", json={"enabled": True, **body})
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def configured(admin, transports):
    _create(admin, kind="qualys", name="Qualys US2", base_url="https://qualysapi.qg2.apps.qualys.com",
            config={"username": "excat_api"}, secrets={"password": "q-pass"})
    _create(admin, kind="wiz", name="Wiz", base_url="https://api.us17.app.wiz.io/graphql",
            config={"client_id": "cid"}, secrets={"client_secret": "w-secret"})
    _create(admin, kind="tanium", name="Tanium", base_url="https://acme-api.cloud.tanium.com",
            secrets={"api_token": "tan-token"})
    _create(admin, kind="servicenow_cmdb", name="CMDB", base_url="https://acme.service-now.com",
            config={"username": "excat"}, secrets={"password": "sn-pass"})
    return transports


# ---- unit ---------------------------------------------------------------------------------------

def test_field_mapping_paths():
    raw = {"a": {"ips": ["10.0.0.1", "10.0.0.2"], "n": [{"x": 1}, {"x": 2}]}, "d": "2026-11-01T10:00:00Z"}
    assert get_path(raw, "a.ips.0") == "10.0.0.1"
    assert get_path(raw, "a.ips") == "10.0.0.1, 10.0.0.2"
    assert get_path(raw, "a.n.x") == "1, 2"
    assert get_path(raw, "=Production") == "Production"
    assert get_path(raw, "missing.path") is None
    rec = map_record(raw, {"ip_address": "a.ips.1", "detection_date": "d", "environment": "=prod"})
    assert rec["ip_address"] == "10.0.0.2" and str(rec["detection_date"]) == "2026-11-01" and rec["environment"] == "prod"


# ---- configuration & security ----------------------------------------------------------------

def test_catalog_and_rbac(admin, login):
    kinds = {c["kind"] for c in admin.get("/api/integrations/catalog").json()}
    assert kinds == {"qualys", "tanium", "wiz", "zafran", "armorcode", "servicenow_cmdb"}
    analyst = login("Security Analyst", username="ana")
    assert analyst.get("/api/integrations").status_code == 403
    assert analyst.post("/api/integrations", json={}).status_code == 403


@pytest.mark.parametrize("url", ["https://evil.example.com", "http://qualysapi.qg2.apps.qualys.com",
                                 "https://169.254.169.254", "https://qualysapi.qualys.com.evil.io",
                                 "https://qualysapi.qg2.apps.qualys.com/?x=1"])
def test_base_url_rejected(admin, url):
    r = admin.post("/api/integrations", json={"kind": "qualys", "name": "Qualys", "base_url": url,
                                              "config": {"username": "u"}, "secrets": {"password": "p"}})
    assert r.status_code == 422 and "Base URL rejected" in r.text


def test_secrets_never_returned_and_validated(admin, transports):
    r = _create(admin, kind="wiz", name="Wiz", base_url="https://api.us17.app.wiz.io/graphql",
                config={"client_id": "cid"}, secrets={"client_secret": "super-secret-value"})
    assert r["secrets_set"] == ["client_secret"] and "super-secret-value" not in json.dumps(r)
    listing = admin.get("/api/integrations").text
    assert "super-secret-value" not in listing
    assert admin.post("/api/integrations", json={"kind": "wiz", "name": "W2", "base_url": "https://api.us17.app.wiz.io/graphql",
                                                 "secrets": {"password": "x"}}).status_code == 422
    assert admin.patch(f"/api/integrations/{r['id']}", json={"config": {"field_map": {"bogus": "x"}}}).status_code == 422
    assert admin.patch(f"/api/integrations/{r['id']}", json={"config": {"nope": 1}}).status_code == 422
    with get_session_factory()() as s:
        enc = s.get(Integration, r["id"]).secrets_enc
        assert enc and "super-secret-value" not in enc


def test_test_connection(admin, configured):
    for i in admin.get("/api/integrations").json():
        r = admin.post(f"/api/integrations/{i['id']}/test").json()
        assert r["ok"], (i["kind"], r["message"])
    q = next(i for i in admin.get("/api/integrations").json() if i["kind"] == "qualys")
    assert q["status"] == "ok" and q["last_test_at"]


# ---- correlation ----------------------------------------------------------------------------

def test_cve_panel_correlates_enriches_and_caches(admin, configured, cve, login, settings):
    viewer = login("Viewer", username="vv")
    assert viewer.get(f"/api/cves/{CVE}/assets").json()["sources"][0]["status"] == "never"
    analyst = login("Security Analyst", username="ana2")
    panel = analyst.post(f"/api/cves/{CVE}/assets/refresh").json()
    by = {s["source"]: s for s in panel["sources"]}
    assert by["Qualys"]["status"] == "ok" and by["Qualys"]["asset_count"] == 2  # paginated via WARNING/URL
    assert by["Wiz"]["asset_count"] == 2 and by["Tanium"]["asset_count"] == 0 and by["ServiceNow CMDB"]["asset_count"] == 1
    # web01 (Qualys host + IP) ≡ WEB01.corp (Wiz, same IP); app02; lambda-x; db03 → 4 unique
    assert panel["total_unique_assets"] == 4
    web = next(a for a in panel["assets"] if a["ip_address"] == "10.0.0.5")
    assert web["sources"] == ["Qualys", "Wiz"] and web["owner"] == "Web Team" and web["environment"] == "Production"
    qualys_calls = len(configured["qualys"].log)
    analyst.get(f"/api/cves/{CVE}/assets")
    with get_session_factory()() as s:
        corr.check_all(s, CVE, settings)
    assert len(configured["qualys"].log) == qualys_calls  # served from cache within TTL
    assert viewer.post(f"/api/cves/{CVE}/assets/refresh").status_code == 403


def test_failure_isolated_and_not_marked_integrated(admin, configured, cve, login, monkeypatch):
    monkeypatch.setitem(corr.TRANSPORTS, "tanium", tanium_transport(Calls(), fail=True))
    analyst = login("Security Analyst", username="ana3")
    a = analyst.post("/api/advisories", json={"cve_id": CVE}).json()
    analyst.post(f"/api/advisories/{a['id']}/assets", json={"source": "Zafran", "hostname": "manual-box"})
    r = analyst.post(f"/api/advisories/{a['id']}/assets/pull", json={}).json()
    status = {x["source"]: x["status"] for x in r["results"]}
    assert status["Tanium"] == "error" and status["Qualys"] == "ok"
    m = {row["source"]: row for row in r["advisory"]["matrix"]}
    assert m["Qualys"]["validated"] == "Yes" and not m["Qualys"]["manual"]
    assert m["Wiz"]["validated"] == "Yes"
    assert m["Tanium"]["validated"] == "Not Integrated"  # failed check is not reported as "No"
    assert m["Zafran"]["validated"] == "Yes" and m["Zafran"]["manual"]  # manual rows survive a pull
    assert m["ArmorCode"]["validated"] == "Not Integrated"
    assert r["advisory"]["total_unique_assets"] == 5
    integ_assets = [x for x in r["advisory"]["assets"] if not x["is_manual"]]
    assert {x["source"] for x in integ_assets} == {"Qualys", "Wiz", "ServiceNow CMDB"}
    # pulling again replaces (not duplicates) integration rows
    r2 = analyst.post(f"/api/advisories/{a['id']}/assets/pull", json={"force": True}).json()
    assert len(r2["advisory"]["assets"]) == len(r["advisory"]["assets"])


def test_tanium_zero_findings_is_no(admin, configured, cve, login):
    analyst = login("Security Analyst", username="ana4")
    a = analyst.post("/api/advisories", json={"cve_id": CVE}).json()
    r = analyst.post(f"/api/advisories/{a['id']}/assets/pull", json={}).json()
    assert {row["source"]: row["validated"] for row in r["advisory"]["matrix"]}["Tanium"] == "No"


def test_qualys_rejects_cross_host_pagination(admin, cve, monkeypatch):
    monkeypatch.setattr(corr, "TRANSPORTS", {"qualys": qualys_transport(Calls(), evil_link=True)})
    _create(admin, kind="qualys", name="Qualys", base_url="https://qualysapi.qg2.apps.qualys.com",
            config={"username": "u"}, secrets={"password": "p"})
    panel = admin.post(f"/api/cves/{CVE}/assets/refresh").json()
    src = panel["sources"][0]
    assert src["status"] == "error" and "different host" in src["error"]


def test_generic_rest_connectors_paginate(admin, cve, monkeypatch, settings):
    def zafran(req):
        assert req.headers["Authorization"] == "Bearer z-tok" and req.url.params["cve"] == CVE
        if req.url.params.get("cursor") is None:
            return httpx.Response(200, json={"data": [{"id": "z1", "asset": {"hostname": "h1", "ip_address": "10.9.0.1"}}],
                                             "next_cursor": "n2"})
        return httpx.Response(200, json={"data": [{"id": "z2", "asset": {"hostname": "h2"}}], "next_cursor": None})

    def armor(req):
        page = int(req.url.params.get("page", 0))
        return httpx.Response(200, json={"content": [{"id": f"a{page}", "asset": {"name": f"ac{page}"}}],
                                         "totalPages": 2})

    monkeypatch.setattr(corr, "TRANSPORTS", {"zafran": httpx.MockTransport(zafran), "armorcode": httpx.MockTransport(armor)})
    _create(admin, kind="zafran", name="Zafran", base_url="https://api.zafran.io", secrets={"api_token": "z-tok"})
    _create(admin, kind="armorcode", name="ArmorCode", base_url="https://app.armorcode.com",
            secrets={"api_token": "a-tok"}, config={"page_size": 1})
    by = {s["source"]: s["asset_count"] for s in admin.post(f"/api/cves/{CVE}/assets/refresh").json()["sources"]}
    assert by == {"Zafran": 2, "ArmorCode": 2}


def test_truncation_flag(admin, cve, monkeypatch, settings):
    settings.connector_max_assets = 100
    nodes = [{"id": f"w{i}", "vulnerableAsset": {"name": f"vm{i}"}} for i in range(150)]

    def h(req):
        if req.url.host.startswith("auth"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 60})
        return httpx.Response(200, json={"data": {"vulnerabilityFindings": {"nodes": nodes,
                                                                            "pageInfo": {"hasNextPage": False}}}})

    monkeypatch.setattr(corr, "TRANSPORTS", {"wiz": httpx.MockTransport(h)})
    _create(admin, kind="wiz", name="Wiz", base_url="https://api.us17.app.wiz.io/graphql",
            config={"client_id": "c"}, secrets={"client_secret": "s"})
    src = admin.post(f"/api/cves/{CVE}/assets/refresh").json()["sources"][0]
    assert src["asset_count"] == 100 and src["truncated"]


def test_servicenow_query_injection_stripped():
    from exposurecatalyst.connectors.servicenow import _q

    assert _q("web01^ORname!=x") == "web01ORname!=x"


def test_qualys_retries_on_concurrency_409(admin, cve, monkeypatch, settings):
    """Qualys signals 'concurrency limit exceeded' with HTTP 409: the connector backs off and retries."""
    hits = {"n": 0}

    def h(req: httpx.Request):
        if req.url.path.endswith("/msp/about.php"):
            hits["n"] += 1
            if hits["n"] == 1:
                return httpx.Response(409, content=b"<SIMPLE_RETURN><RESPONSE><CODE>1960</CODE></RESPONSE></SIMPLE_RETURN>")
            return httpx.Response(200, content=b"<ABOUT><WEB-VERSION>10.30</WEB-VERSION></ABOUT>")
        return httpx.Response(404)

    monkeypatch.setattr(corr, "TRANSPORTS", {"qualys": httpx.MockTransport(h)})
    i = _create(admin, kind="qualys", name="Q409", base_url="https://qualysapi.qg2.apps.qualys.com",
                config={"username": "u"}, secrets={"password": "p"})
    r = admin.post(f"/api/integrations/{i['id']}/test")
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert hits["n"] == 2

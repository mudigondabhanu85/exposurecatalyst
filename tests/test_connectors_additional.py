"""The additional connectors (spec "Additional connectors"): each one's request shape, auth, pagination and
field mapping against a mocked vendor API, plus the action connectors (tickets / chat) end to end."""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx
import pytest

from exposurecatalyst.connectors import REGISTRY
from exposurecatalyst.connectors import service as corr
from exposurecatalyst.connectors.base import map_record
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import Cve, CveProduct, Integration

CVE = "CVE-2024-21762"


@pytest.fixture
def admin(login):
    return login("Admin", username="intadmin")


@pytest.fixture
def cve(app):
    with get_session_factory()() as s:
        s.add(Cve(cve_id=CVE, title="FortiOS SSL VPN out-of-bounds write", description="OOB write.",
                  severity="CRITICAL", cvss_score=9.8, cvss_version="3.1", kev=True, provenance={}, cvss_metrics=[],
                  products=[CveProduct(vendor="fortinet", product="fortios", source="nvd")]))
        s.commit()


def run(kind, handler, settings, *, base_url=None, config=None, secrets=None):
    cls = REGISTRY[kind]
    integ = Integration(kind=kind, name=kind, base_url=base_url or cls.spec.base_url_example, config=config or {})
    conn = cls(integ, secrets or {}, settings, transport=httpx.MockTransport(handler), sleep=lambda s: None)
    try:
        msg = conn.test_connection()
        rows = [map_record(r, conn.field_map) for r in conn.iter_findings(CVE)]
    finally:
        conn.close()
    return msg, rows


def body(req: httpx.Request):
    return json.loads(req.content) if req.content else {}


# ---- asset-source connectors -----------------------------------------------------------------------

def test_tenable_io(settings):
    def h(req):
        assert req.headers["X-ApiKeys"] == "accessKey=ak;secretKey=sk"
        if req.url.path == "/session":
            return httpx.Response(200, json={"username": "api@corp"})
        p = req.url.params
        assert req.url.path == "/workbenches/assets" and p["filter.0.filter"] == "plugin.attributes.cve.raw"
        assert p["filter.0.value"] == CVE and p["date_range"] == "30"
        return httpx.Response(200, json={"assets": [
            {"id": "u1", "fqdn": ["web01.corp"], "ipv4": ["10.0.0.5"], "operating_system": ["RHEL 9"],
             "last_seen": "2026-11-10T00:00:00Z"},
            {"id": "u2", "fqdn": [], "netbios_name": ["APP02"], "ipv4": ["10.0.0.9"]}]})
    msg, rows = run("tenable_io", h, settings, secrets={"access_key": "ak", "secret_key": "sk"})
    assert "api@corp" in msg
    assert rows[0]["hostname"] == "web01.corp" and rows[0]["os"] == "RHEL 9" and str(rows[0]["detection_date"]) == "2026-11-10"
    assert rows[1]["hostname"] == "APP02"


def test_tenable_sc_pages_and_epoch_dates(settings):
    settings.egress_allowlist += ",sc.corp.example"
    def h(req):
        assert req.headers["x-apikey"] == "accesskey=ak; secretkey=sk;"
        if req.url.path == "/rest/currentUser":
            return httpx.Response(200, json={"error_code": 0, "response": {"username": "svc"}})
        q = body(req)["query"]
        assert q["tool"] == "listvuln" and q["filters"][0] == {"filterName": "cveID", "operator": "=", "value": CVE}
        start = q["startOffset"]
        results = [{"ip": f"10.1.0.{start + i}", "dnsName": "", "netbiosName": f"H{start + i}", "pluginID": "1",
                    "firstSeen": "1762300800", "repository": {"name": "DC1"}} for i in range(1000 if start == 0 else 3)]
        return httpx.Response(200, json={"error_code": 0, "response": {"totalRecords": "1003", "results": results}})
    _, rows = run("tenable_sc", h, settings, base_url="https://sc.corp.example",
                  secrets={"access_key": "ak", "secret_key": "sk"})
    assert len(rows) == 1003 and rows[0]["hostname"] == "H0" and rows[0]["business_unit"] == "DC1"
    assert str(rows[0]["detection_date"]) == "2025-11-05"


def test_tenable_sc_requires_allowlist(admin):
    r = admin.post("/api/integrations", json={"kind": "tenable_sc", "name": "SC", "base_url": "https://sc.other.example",
                                              "secrets": {"access_key": "a", "secret_key": "b"}})
    assert r.status_code == 422 and "self-hosted" in r.text


def test_rapid7_cursor(settings):
    def h(req):
        assert req.headers["X-Api-Key"] == "r7" and req.url.path == "/vm/v4/integration/assets"
        b = body(req)
        if not b:
            return httpx.Response(200, json={"data": [], "metadata": {}})
        assert b["vulnerability"] == f"vulnerability.cveIds IN ['{CVE}']"
        if "cursor" not in req.url.params:
            return httpx.Response(200, json={"data": [{"id": "a1", "host_name": "web01", "ip": "10.0.0.5"}],
                                             "metadata": {"cursor": "c2"}})
        return httpx.Response(200, json={"data": [{"id": "a2", "host_name": "db01", "ip": "10.0.0.7"}], "metadata": {}})
    _, rows = run("rapid7", h, settings, secrets={"api_key": "r7"})
    assert [r["hostname"] for r in rows] == ["web01", "db01"]


def test_crowdstrike_oauth_filter_and_paging(settings):
    tokens = []
    def h(req):
        if req.url.path == "/oauth2/token":
            tokens.append(1)
            assert parse_qs(req.content.decode())["client_id"] == ["cid"]
            return httpx.Response(201, json={"access_token": "cs", "expires_in": 1799})
        assert req.headers["Authorization"] == "Bearer cs"
        if "queries" in req.url.path:
            return httpx.Response(200, json={"resources": ["x"], "meta": {}})
        assert req.url.params["filter"] == f"cve.id:'{CVE}'+status:['open','reopen']"
        if "after" not in req.url.params:
            return httpx.Response(200, json={"resources": [{"id": "v1", "created_timestamp": "2026-11-01T00:00:00Z",
                "host_info": {"hostname": "WS-01", "local_ip": "10.2.0.1", "os_version": "Windows 11",
                              "groups": [{"name": "Finance"}]}}], "meta": {"pagination": {"after": "tok2"}}})
        return httpx.Response(200, json={"resources": [{"id": "v2", "host_info": {"hostname": "WS-02"}}],
                                         "meta": {"pagination": {}}})
    _, rows = run("crowdstrike", h, settings, config={"client_id": "cid"}, secrets={"client_secret": "s"})
    assert len(tokens) == 1 and rows[0]["business_unit"] == "Finance" and rows[1]["hostname"] == "WS-02"


def test_crowdstrike_fql_injection_stripped(settings):
    from exposurecatalyst.connectors.crowdstrike import _fql
    assert _fql("open'+cid:'x") == "opencid:x"


def test_defender_dedupes_devices_and_resolves_ip(settings):
    def h(req):
        if req.url.host == "login.microsoftonline.com":
            assert req.url.path == "/contoso.onmicrosoft.com/oauth2/v2.0/token"
            assert "scope=https%3A%2F%2Fapi.securitycenter.microsoft.com%2F.default" in req.content.decode()
            return httpx.Response(200, json={"access_token": "md", "expires_in": 3599})
        assert req.headers["Authorization"] == "Bearer md"
        if req.url.path == "/api/vulnerabilities":
            return httpx.Response(200, json={"value": []})
        if req.url.path == "/api/machines/SoftwareVulnerabilitiesByMachine":
            if "$filter" in req.url.params:
                assert req.url.params["$filter"] == f"cveId eq '{CVE}'"
                return httpx.Response(200, json={"value": [
                    {"id": "r1", "deviceId": "d1", "deviceName": "laptop1", "osPlatform": "Windows11",
                     "firstSeenTimestamp": "2026-11-03T00:00:00Z"},
                    {"id": "r2", "deviceId": "d1", "deviceName": "laptop1"}],
                    "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/machines/"
                                       "SoftwareVulnerabilitiesByMachine?$skiptoken=2"})
            return httpx.Response(200, json={"value": [{"id": "r3", "deviceId": "d2", "deviceName": "srv2"}]})
        if req.url.path.startswith("/api/machines/"):
            return httpx.Response(200, json={"lastIpAddress": "10.3.0." + req.url.path[-1]})
        return httpx.Response(404)
    _, rows = run("defender", h, settings, config={"tenant_id": "contoso.onmicrosoft.com", "client_id": "c"},
                  secrets={"client_secret": "s"})
    assert [(r["hostname"], r["ip_address"]) for r in rows] == [("laptop1", "10.3.0.1"), ("srv2", "10.3.0.2")]


def test_defender_rejects_foreign_next_link(settings):
    def h(req):
        if req.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "md", "expires_in": 3599})
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example/x"})
    with pytest.raises(Exception, match="another host"):
        run("defender", h, settings, config={"tenant_id": "t1", "client_id": "c"}, secrets={"client_secret": "s"})


def test_prisma_cloud_hosts_and_containers(settings):
    def h(req):
        if req.url.path.endswith("/api/v1/authenticate"):
            assert body(req) == {"username": "AK", "password": "SK"}
            return httpx.Response(200, json={"token": "pc"})
        assert req.headers["Authorization"] == "Bearer pc"
        if req.url.path.endswith("/api/v1/stats/vulnerabilities"):
            return httpx.Response(200, json=[])
        assert req.url.params["cve"] == CVE
        return httpx.Response(200, json={"_id": CVE, "hosts": [{"resourceID": "node-1"}], "images": [
            {"resourceID": "nginx:1.25", "containers": [{"image": "nginx:1.25", "container": "web-7f", "host": "node-1"}]}]})
    _, rows = run("prisma_cloud", h, settings, base_url="https://us-east1.cloud.twistlock.com/us-1-23",
                  config={"access_key": "AK"}, secrets={"secret_key": "SK"})
    assert [(r["hostname"], r["resource_id"]) for r in rows] == [("node-1", "node-1"), ("node-1", "web-7f")]


def test_snyk_reporting_filter(settings):
    org = "11111111-2222-3333-4444-555555555555"
    def h(req):
        assert req.headers["Authorization"] == "token sn"
        if req.url.path == f"/rest/orgs/{org}":
            return httpx.Response(200, json={"data": {"attributes": {"name": "Acme"}}})
        assert body(req)["filters"]["identifier"] == CVE and body(req)["filters"]["orgs"] == [org]
        return httpx.Response(200, json={"total": 1, "results": [{"issue": {"id": "SNYK-1"}, "introducedDate": "2026-10-01",
                                                                  "project": {"id": "p1", "name": "acme/web:pom.xml"}}]})
    msg, rows = run("snyk", h, settings, config={"org_ids": org}, secrets={"api_token": "sn"})
    assert "Acme" in msg and rows[0]["hostname"] == "acme/web:pom.xml"
    with pytest.raises(Exception, match="UUID"):
        run("snyk", h, settings, config={"org_ids": "not-a-uuid"}, secrets={"api_token": "sn"})


def test_kenna_exact_cve_and_asset_lookup(settings):
    lookups = []
    def h(req):
        assert req.headers["X-Risk-Token"] == "kt"
        if req.url.path == "/asset_groups":
            return httpx.Response(200, json={"asset_groups": []})
        if req.url.path.startswith("/assets/"):
            lookups.append(req.url.path)
            return httpx.Response(200, json={"asset": {"hostname": "h" + req.url.path[-1], "ip_address": "10.4.0.1"}})
        assert req.url.params["q"] == f'cve:"{CVE}"'
        return httpx.Response(200, json={"meta": {"pages": 1}, "vulnerabilities": [
            {"id": 1, "cve_id": CVE, "asset_id": 7}, {"id": 2, "cve_id": CVE, "asset_id": 7},
            {"id": 3, "cve_id": "CVE-2024-99999", "asset_id": 8}]})
    _, rows = run("kenna", h, settings, secrets={"api_token": "kt"})
    assert len(rows) == 2 and rows[0]["hostname"] == "h7" and lookups == ["/assets/7"]


def test_axonius_aql_and_dotted_keys(settings):
    def h(req):
        assert req.headers["api-key"] == "k" and req.headers["api-secret"] == "s"
        if req.method == "GET":
            return httpx.Response(200, json={"data": {"attributes": {"Version": "6.1"}}})
        attrs = body(req)["data"]["attributes"]
        assert attrs["filter"] == f'("specific_data.data.software_cves.cve_id" == "{CVE}")'
        return httpx.Response(200, json={"data": [{"id": "ax1", "attributes": {
            "specific_data.data.hostname": ["web01", "WEB01"], "specific_data.data.network_interfaces.ips": ["10.0.0.5"],
            "specific_data.data.os.type_distribution": ["Linux RHEL"], "labels": ["Production"]}}]})
    msg, rows = run("axonius", h, settings, secrets={"api_key": "k", "api_secret": "s"})
    assert "6.1" in msg
    assert rows[0] == {**rows[0], "hostname": "web01", "ip_address": "10.0.0.5", "os": "Linux RHEL",
                       "environment": "Production", "source_ref": "ax1"}


def test_armis_token_and_paging(settings):
    def h(req):
        if req.url.path == "/api/v1/access_token/":
            return httpx.Response(200, json={"data": {"access_token": "at", "expiration_utc": "2099-01-01T00:00:00Z"}})
        assert req.headers["Authorization"] == "at"
        if "vulnerabilities" not in req.url.params["aql"]:
            return httpx.Response(200, json={"success": True, "data": {"results": []}})
        assert req.url.params["aql"] == f'in:devices vulnerabilities:(id:"{CVE}")'
        start = int(req.url.params["from"])
        return httpx.Response(200, json={"success": True, "data": {
            "results": [{"id": start + 1, "name": f"cam{start}", "ipAddress": "10.5.0.1", "site": {"name": "HQ"}}],
            "next": 1 if start == 0 else None}})
    _, rows = run("armis", h, settings, secrets={"secret_key": "sk"})
    assert [r["hostname"] for r in rows] == ["cam0", "cam1"] and rows[0]["business_unit"] == "HQ"


def test_runzero_export(settings):
    def h(req):
        assert req.headers["Authorization"] == "Bearer rz"
        if req.url.path.endswith("sites.json"):
            return httpx.Response(200, json=[])
        assert req.url.params["search"] == f'cve:"{CVE}"'
        return httpx.Response(200, json=[
            {"vulnerability_id": "v1", "vulnerability_cve": CVE, "asset_id": "a1", "names": ["fw01"],
             "addresses": ["10.6.0.1"], "vulnerability_first_detected_ts": 1762300800},
            {"vulnerability_id": "v2", "vulnerability_cve": "CVE-2020-0001", "asset_id": "a2", "names": ["x"]}])
    _, rows = run("runzero", h, settings, secrets={"api_token": "rz"})
    assert len(rows) == 1 and rows[0]["hostname"] == "fw01" and str(rows[0]["detection_date"]) == "2025-11-05"


def test_checkmarx_walks_projects(settings):
    def h(req):
        if req.url.host == "iam.checkmarx.net":
            assert req.url.path == "/auth/realms/acme/protocol/openid-connect/token"
            assert "grant_type=refresh_token" in req.content.decode()
            return httpx.Response(200, json={"access_token": "cx", "expires_in": 1800})
        assert req.headers["Authorization"] == "Bearer cx"
        if req.url.path == "/api/projects":
            return httpx.Response(200, json={"totalCount": 2, "projects": [{"id": "p1", "name": "web"}, {"id": "p2", "name": "api"}]})
        if req.url.path == "/api/projects/last-scan":
            assert req.url.params.get_list("project-ids") == ["p1", "p2"]
            return httpx.Response(200, json={"p1": {"id": "s1"}, "p2": {"id": "s2"}})
        if req.url.path == "/api/results":
            sid = req.url.params["scan-id"]
            res = [{"type": "sca", "id": CVE, "similarityId": f"{sid}-1", "state": "TO_VERIFY",
                    "data": {"packageIdentifier": "Maven-log4j-core-2.14.1"}},
                   {"type": "sast", "id": "x"}, {"type": "sca", "id": CVE, "state": "NOT_EXPLOITABLE"}]
            return httpx.Response(200, json={"totalCount": 3, "results": res if sid == "s1" else []})
        return httpx.Response(404)
    _, rows = run("checkmarx", h, settings, config={"tenant": "acme"}, secrets={"api_key": "rt"})
    assert len(rows) == 1 and rows[0]["hostname"] == "web" and rows[0]["os"] == "Maven-log4j-core-2.14.1"


def test_mend_login_and_project_findings(settings):
    org = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    def h(req):
        if req.url.path == "/api/v3.0/login":
            assert body(req) == {"email": "svc@corp", "userKey": "uk", "orgUuid": org}
            return httpx.Response(200, json={"response": {"refreshToken": "rt"}})
        if req.url.path == "/api/v3.0/login/accessToken":
            assert req.headers["wss-refresh-token"] == "rt"
            return httpx.Response(200, json={"response": {"jwtToken": "jw", "jwtTTL": 1800000}})
        assert req.headers["Authorization"] == "Bearer jw"
        if req.url.path.endswith("/projects"):
            return httpx.Response(200, json={"response": [{"uuid": "p1", "name": "payments"}], "additionalData": {}})
        assert req.url.params["search"] == f"vulnerabilityName:equals:{CVE}"
        return httpx.Response(200, json={"response": [
            {"uuid": "f1", "vulnerability": {"name": CVE}, "component": {"name": "log4j-core-2.14.1.jar"},
             "findingInfo": {"status": "ACTIVE"}},
            {"uuid": "f2", "vulnerability": {"name": CVE}, "findingInfo": {"status": "IGNORED"}}]})
    _, rows = run("mend", h, settings, config={"email": "svc@corp", "org_uuid": org}, secrets={"user_key": "uk"})
    assert len(rows) == 1 and rows[0]["hostname"] == "payments" and rows[0]["os"] == "log4j-core-2.14.1.jar"


@pytest.mark.parametrize("kind,base", [("brinqa", "https://acme.brinqa.net"), ("orca", "https://api.orcasecurity.io")])
def test_rest_post_templates_paginate_in_body(settings, kind, base):
    seen = []
    def h(req):
        b = body(req)
        if req.method == "GET":
            return httpx.Response(200, json={})
        seen.append(b)
        assert CVE in json.dumps(b)
        key = REGISTRY[kind].spec.fields
        page_param = next(f.default for f in key if f.key == "page_param")
        start = b.get(page_param, 0)
        rows = [{"id": f"r{start + i}", "uid": f"r{start + i}", "targets": [{"hostnames": [f"h{start + i}"]}],
                 "data": {"Asset": {"name": f"h{start + i}"}}} for i in range(2 if start == 0 else 1)]
        return httpx.Response(200, json={"data": rows, "total_items": 3})
    _, rows = run(kind, h, settings, base_url=base, config={"page_size": 2}, secrets={"api_token": "t"})
    assert [r["hostname"] for r in rows] == ["h0", "h1", "h2"]
    assert seen[0]["limit"] == 2  # "{{limit}}" substituted as a number


def test_nucleus_path_variable(settings):
    def h(req):
        assert req.headers["x-apikey"] == "nk"
        if req.method == "GET":
            assert req.url.path == "/nucleus/api/projects/42"
            return httpx.Response(200, json={})
        assert req.url.path == "/nucleus/api/projects/42/findings/search" and body(req)["finding_cve"] == CVE
        return httpx.Response(200, json=[{"finding_number": "N1", "asset_name": "srv9", "ip_address": "10.7.0.9"}])
    _, rows = run("nucleus", h, settings, base_url="https://acme.nucleussec.com", config={"project_id": "42"},
                  secrets={"api_token": "nk"})
    assert rows[0]["hostname"] == "srv9"


def test_every_connector_has_docs_and_valid_spec():
    import pathlib
    docs = pathlib.Path(__file__).resolve().parents[1] / "docs"
    for kind, cls in REGISTRY.items():
        s = cls.spec
        assert s.api_status in ("documented", "confirm") and s.category
        assert (docs / (s.docs.rstrip("/") + ".md")).exists(), f"missing guide for {kind}: {s.docs}"
        for _label, url in s.regions:
            assert url.startswith("https://")


# ---- API: asset sources vs action connectors ------------------------------------------------------

def _create(c, **body):
    r = c.post("/api/integrations", json={"enabled": True, **body})
    assert r.status_code == 201, r.text
    return r.json()


def test_action_connectors_are_not_asset_sources(admin, cve, monkeypatch):
    monkeypatch.setattr(corr, "TRANSPORTS", {"slack": httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": True}))})
    s = _create(admin, kind="slack", name="Slack #vuln", config={"channel": "C1"}, secrets={"bot_token": "xoxb-1"})
    assert s["base_url"] == "https://slack.com"  # fixed endpoint, no URL needed
    panel = admin.post(f"/api/cves/{CVE}/assets/refresh").json()
    assert panel["sources"] == [] and not panel["integrations_configured"]


def test_webhook_secret_host_validated(admin):
    r = admin.post("/api/integrations", json={"kind": "teams", "name": "Teams",
                                              "secrets": {"webhook_url": "https://evil.example/hook"}})
    assert r.status_code == 422 and "webhook" in r.text
    r = admin.post("/api/integrations", json={"kind": "slack", "name": "Slack",
                                              "secrets": {"webhook_url": "http://hooks.slack.com/services/x"}})
    assert r.status_code == 422


def _advisory(login):
    analyst = login("Security Analyst", username="ana-adv")
    r = analyst.post("/api/advisories", json={"cve_id": CVE})
    assert r.status_code == 201, r.text
    return r.json(), analyst


@pytest.fixture
def approved_advisory(cve, login):
    adv, analyst = _advisory(login)
    analyst.patch(f"/api/advisories/{adv['id']}", json={"to_addrs": ["ops@example.com"]})
    analyst.post(f"/api/advisories/{adv['id']}/assets", json={"source": "Qualys", "hostname": "web01.corp",
                                                             "ip_address": "10.0.0.5"})
    assert analyst.post(f"/api/advisories/{adv['id']}/submit").status_code == 200
    r = login("Approver", username="apu-adv").post(f"/api/advisories/{adv['id']}/approve", json={"comment": "ok"})
    assert r.status_code == 200, r.text
    return {**r.json(), "client": analyst}


def test_create_tickets_and_posts(admin, approved_advisory, monkeypatch, login):
    sent = {}

    def jira(req):
        if req.method == "GET":
            return httpx.Response(200, json={"key": "SEC", "name": "Security"})
        sent["jira"] = b = body(req)
        assert req.headers["Authorization"].startswith("Basic ") and req.url.path == "/rest/api/3/issue"
        f = b["fields"]
        assert f["project"] == {"key": "SEC"} and f["summary"].startswith("[") and CVE in f["summary"]
        assert f["description"]["type"] == "doc" and "exposurecatalyst" in f["labels"]
        return httpx.Response(201, json={"key": "SEC-101"})

    def snow(req):
        if req.method == "GET":
            return httpx.Response(200, json={"result": []})
        sent["snow"] = b = body(req)
        assert b["correlation_id"] == approved_advisory["advisory_id"] and b["impact"] in ("1", "2", "3")
        return httpx.Response(201, json={"result": {"sys_id": "abc", "number": "INC0010001"}})

    def teams(req):
        sent["teams"] = body(req)
        return httpx.Response(202)

    monkeypatch.setattr(corr, "TRANSPORTS", {"jira": httpx.MockTransport(jira), "servicenow_itsm": httpx.MockTransport(snow),
                                             "teams": httpx.MockTransport(teams)})
    j = _create(admin, kind="jira", name="Jira SEC", base_url="https://acme.atlassian.net",
                config={"email": "svc@acme.com", "project_key": "SEC"}, secrets={"api_token": "jt"})
    sn = _create(admin, kind="servicenow_itsm", name="SN Incidents", base_url="https://acme.service-now.com",
                 config={"username": "excat"}, secrets={"password": "p"})
    t = _create(admin, kind="teams", name="Teams SecOps",
                secrets={"webhook_url": "https://prod-1.westus.logic.azure.com/workflows/x?sig=y"})
    for i in (j, sn):
        assert admin.post(f"/api/integrations/{i['id']}/test").json()["ok"]

    pk, analyst = approved_advisory["id"], approved_advisory["client"]
    listing = analyst.get(f"/api/advisories/{pk}/actions").json()
    assert listing["allowed"] and {a["kind"] for a in listing["available"]} == {"jira", "servicenow_itsm", "teams"}

    r = analyst.post(f"/api/advisories/{pk}/actions", json={"integration_id": j["id"]})
    assert r.status_code == 201 and r.json()["ref"] == "SEC-101" and r.json()["url"] == "https://acme.atlassian.net/browse/SEC-101"
    assert analyst.post(f"/api/advisories/{pk}/actions", json={"integration_id": sn["id"]}).json()["ref"] == "INC0010001"
    assert analyst.post(f"/api/advisories/{pk}/actions", json={"integration_id": t["id"]}).json()["status"] == "ok"
    card = sent["teams"]["attachments"][0]["content"]
    assert card["actions"][0]["url"].endswith(f"/advisories/{pk}")
    hist = analyst.get(f"/api/advisories/{pk}/actions").json()["history"]
    assert len(hist) == 3 and {h["status"] for h in hist} == {"ok"}
    audit = admin.get("/api/audit", params={"action": "advisory.ticket_created"})
    if audit.status_code == 200:
        assert "SEC-101" in audit.text

    assert admin.post(f"/api/advisories/{pk}/actions", json={"integration_id": j["id"]}).status_code == 403
    viewer = login("Approver", username="appr-act")  # approvers can view but not send
    assert viewer.get(f"/api/advisories/{pk}/actions").status_code == 200
    assert viewer.post(f"/api/advisories/{pk}/actions", json={"integration_id": j["id"]}).status_code == 403


def test_actions_need_approved_advisory_and_action_kind(admin, cve, monkeypatch, login):
    monkeypatch.setattr(corr, "TRANSPORTS", {})
    a, analyst = _advisory(login)
    z = _create(admin, kind="zafran", name="Zafran", base_url="https://api.zafran.io", secrets={"api_token": "z"})
    assert analyst.get(f"/api/advisories/{a['id']}/actions").json()["allowed"] is False
    assert analyst.post(f"/api/advisories/{a['id']}/actions", json={"integration_id": z["id"]}).status_code == 409


def test_failed_delivery_recorded(admin, approved_advisory, monkeypatch):
    monkeypatch.setattr(corr, "TRANSPORTS", {"slack": httpx.MockTransport(
        lambda r: httpx.Response(200, json={"ok": False, "error": "channel_not_found"}))})
    s = _create(admin, kind="slack", name="Slack", config={"channel": "C9"}, secrets={"bot_token": "xoxb-2"})
    r = approved_advisory["client"].post(f"/api/advisories/{approved_advisory['id']}/actions", json={"integration_id": s["id"]}).json()
    assert r["status"] == "error" and "channel_not_found" in r["error"]

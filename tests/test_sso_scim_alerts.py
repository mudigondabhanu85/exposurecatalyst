from __future__ import annotations

import base64
import re
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from exposurecatalyst.alerts import engine
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import AlertEvent, Cve, CveProduct, Role, SamlRequest, User, UserSession
from tests.conftest import PASSWORD, ApiClient

IDP_ENTITY = "http://www.okta.com/exk-test"
IDP_SSO = "https://acme.okta.com/app/acme_excat/exk-test/sso/saml"
ACS = "http://localhost:8000/api/auth/saml/acs"
SP_ENTITY = "http://localhost:8000/api/saml/metadata"


@pytest.fixture(scope="module")
def idp_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode(),
            cert.public_bytes(serialization.Encoding.PEM).decode())


def idp_metadata(cert_pem: str) -> str:
    body = "".join(cert_pem.strip().splitlines()[1:-1])
    return (f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}">'
            f'<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>'
            f'<ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_SSO}"/>'
            f'</md:IDPSSODescriptor></md:EntityDescriptor>')


def saml_response(keys, *, in_response_to: str | None, email="ana@acme.com", groups=("ExcatAnalysts",),
                  audience=SP_ENTITY, sign=True, tamper_group: str | None = None) -> str:
    key, cert = keys
    now = datetime.now(UTC)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    later, before = (now + timedelta(minutes=5)).strftime(fmt), (now - timedelta(minutes=1)).strftime(fmt)
    irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    attr_vals = "".join(f'<saml:AttributeValue xsi:type="xs:string">{g}</saml:AttributeValue>' for g in groups)
    assertion = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" '
        f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_a{uuid.uuid4().hex}" IssueInstant="{now.strftime(fmt)}" Version="2.0">'
        f'<saml:Issuer>{IDP_ENTITY}</saml:Issuer>'
        f'<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData{irt} '
        f'NotOnOrAfter="{later}" Recipient="{ACS}"/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{before}" NotOnOrAfter="{later}"><saml:AudienceRestriction>'
        f'<saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{now.strftime(fmt)}" SessionIndex="_s1"><saml:AuthnContext>'
        f'<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>'
        f'</saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>'
        f'<saml:Attribute Name="email"><saml:AttributeValue xsi:type="xs:string">{email}</saml:AttributeValue></saml:Attribute>'
        f'<saml:Attribute Name="firstName"><saml:AttributeValue xsi:type="xs:string">Ana</saml:AttributeValue></saml:Attribute>'
        f'<saml:Attribute Name="groups">{attr_vals}</saml:Attribute></saml:AttributeStatement></saml:Assertion>')
    if sign:
        assertion = OneLogin_Saml2_Utils.add_sign(assertion, key, cert, sign_algorithm=C.RSA_SHA256,
                                                  digest_algorithm=C.SHA256).decode()
        assertion = re.sub(r"^<\?xml[^>]*\?>", "", assertion)
    if tamper_group:
        assertion = assertion.replace(">ExcatAnalysts<", f">{tamper_group}<")
    resp = (f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="_r{uuid.uuid4().hex}" Version="2.0" IssueInstant="{now.strftime(fmt)}" Destination="{ACS}"{irt}>'
            f'<saml:Issuer>{IDP_ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode '
            f'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>')
    return base64.b64encode(resp.encode()).decode()


@pytest.fixture
def root(login):
    return login("Super Admin", username="root")


@pytest.fixture
def saml_on(root, idp_keys):
    assert root.post("/api/settings/sso/saml/metadata", json={"xml": idp_metadata(idp_keys[1])}).status_code == 200
    roles = {r["name"]: r["id"] for r in root.get("/api/admin/rbac").json()["roles"]}
    assert root.put("/api/settings/sso/saml", json={"enabled": True}).status_code == 422  # PUT is a full replace: IdP fields required
    cfg = root.get("/api/settings/sso/saml").json()
    body = {k: cfg[k] for k in ("idp_entity_id", "idp_sso_url", "idp_x509_cert")} | {"enabled": True}
    r = root.put("/api/settings/sso/saml", json=body)
    assert r.status_code == 422 and "Map at least one group" in r.text  # no mapping yet → refuse
    assert root.post("/api/settings/sso/mappings", json={"group_name": "ExcatAnalysts",
                                                         "role_id": roles["Security Analyst"]}).status_code == 201
    assert root.put("/api/settings/sso/saml", json=body).status_code == 200
    return roles


def start_login(app, next_path="/advisories"):
    c = ApiClient(app)
    c.__enter__()
    r = c.get("/api/auth/saml/login", params={"next": next_path}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(IDP_SSO + "?SAMLRequest=")
    with get_session_factory()() as s:
        rid = s.query(SamlRequest).order_by(SamlRequest.created_at.desc()).first().id
    return c, rid


def acs(c, saml_b64):
    return c.post("/api/auth/saml/acs", data={"SAMLResponse": saml_b64},
                  headers={"Origin": "https://acme.okta.com"}, follow_redirects=False)


# ---- SAML --------------------------------------------------------------------------------------

def test_sp_metadata_download(client):
    r = client.get("/api/saml/metadata")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert f'Location="{ACS}"' in r.text and f'entityID="{SP_ENTITY}"' in r.text
    assert "<ds:X509Certificate>" in r.text and "PRIVATE" not in r.text


def test_saml_login_maps_groups_to_roles(app, saml_on, idp_keys):
    c, rid = start_login(app)
    r = acs(c, saml_response(idp_keys, in_response_to=rid))
    assert r.status_code == 200 and 'url=/advisories"' in r.text  # same-origin meta-refresh hop
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    me = c.get("/api/auth/me").json()
    assert me["username"] == "ana@acme.com" and me["roles"] == ["Security Analyst"] and me["mfa_verified"]
    with get_session_factory()() as s:
        u = s.query(User).filter_by(username="ana@acme.com").one()
        assert not u.is_local and u.auth_source == "saml" and u.sso_groups == ["ExcatAnalysts"] and u.password_hash is None


@pytest.mark.parametrize("variant", ["replay", "unsigned", "tampered", "wrong_audience", "unknown_request",
                                     "idp_initiated", "unmapped_group"])
def test_saml_rejections(app, saml_on, idp_keys, variant):
    c, rid = start_login(app)
    kw = {"in_response_to": rid}
    if variant == "replay":
        ok = saml_response(idp_keys, **kw)
        assert "url=/advisories" in acs(c, ok).text
        c2, _ = start_login(app)
        r = acs(c2, ok)
    else:
        kw.update({"unsigned": {"sign": False}, "tampered": {"tamper_group": "ExcatAdmins"},
                   "wrong_audience": {"audience": "https://evil.example/sp"},
                   "unknown_request": {"in_response_to": "_forged"}, "idp_initiated": {"in_response_to": None},
                   "unmapped_group": {"groups": ("Marketing",)}}[variant])
        r = acs(c, saml_response(idp_keys, **kw))
    assert "url=/login?sso_error=" in r.text, variant
    assert not any(k.startswith("excat_session") for k in r.cookies), variant


def test_saml_cannot_take_over_local_account(app, saml_on, idp_keys, make_user):
    make_user("breakglass@acme.com", "Super Admin")
    c, rid = start_login(app)
    r = acs(c, saml_response(idp_keys, in_response_to=rid, email="breakglass@acme.com"))
    assert "sso_error=" in r.text and "local" in r.text


def test_open_redirect_blocked(app, saml_on, idp_keys):
    c, rid = start_login(app, next_path="//evil.example/x")
    r = acs(c, saml_response(idp_keys, in_response_to=rid))
    assert 'url=/cves"' in r.text


def test_mapping_change_recomputes_roles(app, root, saml_on, idp_keys):
    c, rid = start_login(app)
    acs(c, saml_response(idp_keys, in_response_to=rid))
    m = root.get("/api/settings/sso/mappings").json()
    assert m["mappings"][0]["users"] == 1 and m["sso_users"] == 1
    root.delete(f"/api/settings/sso/mappings/{m['mappings'][0]['id']}")
    assert c.get("/api/auth/me").status_code == 401  # role change revoked the session
    with get_session_factory()() as s:
        assert s.query(User).filter_by(username="ana@acme.com").one().roles == []
    uid = next(u["id"] for u in root.get("/api/admin/users").json() if u["username"] == "ana@acme.com")
    r = root.put(f"/api/admin/users/{uid}/roles", json={"role_ids": [saml_on["Viewer"]]})
    assert r.status_code == 409 and "group" in r.text


# ---- SCIM --------------------------------------------------------------------------------------

@pytest.fixture
def scim(app, root, saml_on):
    tok = root.post("/api/settings/scim/tokens", json={"name": "SailPoint ISC"}).json()
    c = ApiClient(app)
    c.__enter__()
    c.headers["Authorization"] = f"Bearer {tok['token']}"
    return c, tok


def test_scim_auth(app, scim, root):
    anon = ApiClient(app)
    r = anon.get("/scim/v2/Users")
    assert r.status_code == 401 and r.headers["content-type"].startswith("application/scim+json")
    assert r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    c, tok = scim
    assert c.get("/scim/v2/ServiceProviderConfig").json()["patch"]["supported"] is True
    tid = root.get("/api/settings/scim/tokens").json()[0]["id"]
    root.delete(f"/api/settings/scim/tokens/{tid}")
    assert c.get("/scim/v2/Users").status_code == 401


def test_scim_lifecycle_drives_roles(scim, make_user):
    c, _ = scim
    u = c.post("/scim/v2/Users", json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "Bob@Acme.com",
                                       "externalId": "sp-123", "name": {"givenName": "Bob", "familyName": "B"},
                                       "emails": [{"value": "bob@acme.com", "primary": True}], "active": True})
    assert u.status_code == 201
    uid = u.json()["id"]
    assert c.post("/scim/v2/Users", json={"userName": "bob@acme.com"}).json()["scimType"] == "uniqueness"
    found = c.get("/scim/v2/Users", params={"filter": 'userName eq "BOB@acme.com"'}).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["externalId"] == "sp-123"
    assert c.get("/scim/v2/Users", params={"filter": "userName co \"b\""}).status_code == 400

    g = c.post("/scim/v2/Groups", json={"displayName": "ExcatAnalysts", "members": [{"value": uid}]}).json()
    with get_session_factory()() as s:
        bob = s.query(User).filter_by(username="bob@acme.com").one()
        assert [r.name for r in bob.roles] == ["Security Analyst"] and bob.sso_groups == ["ExcatAnalysts"]
    assert c.get(f"/scim/v2/Users/{uid}").json()["groups"][0]["display"] == "ExcatAnalysts"

    c.patch(f"/scim/v2/Groups/{g['id']}", json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                               "Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    with get_session_factory()() as s:
        assert s.query(User).filter_by(username="bob@acme.com").one().roles == []

    c.patch(f"/scim/v2/Groups/{g['id']}", json={"Operations": [{"op": "add", "path": "members", "value": [{"value": uid}]}]})
    r = c.patch(f"/scim/v2/Users/{uid}", json={"Operations": [{"op": "replace", "value": {"active": False}}]})
    assert r.json()["active"] is False
    assert c.delete(f"/scim/v2/Users/{uid}").status_code == 204
    with get_session_factory()() as s:
        bob = s.query(User).filter_by(username="bob@acme.com").one()
        assert not bob.is_active and bob.roles == []

    make_user("local@acme.com", "Viewer")
    assert c.post("/scim/v2/Users", json={"userName": "local@acme.com"}).status_code == 409


# ---- alerts ------------------------------------------------------------------------------------

@pytest.fixture
def alert_env(app, root, monkeypatch):
    sent = {"emails": [], "slack": []}
    from exposurecatalyst.advisories import delivery

    monkeypatch.setattr(delivery, "send", lambda msg, to, cfg, settings: sent["emails"].append((msg["Subject"], to)) or "<id>")
    monkeypatch.setattr(engine, "TRANSPORTS", {"slack": httpx.MockTransport(
        lambda req: sent["slack"].append(req.content) or httpx.Response(200, text="ok"))})
    from exposurecatalyst.advisories.delivery import SmtpConfig
    from exposurecatalyst.api import smtp

    monkeypatch.setattr(smtp, "load_config", lambda db: SmtpConfig("smtp.example.com", 587, "starttls", None, None,
                                                                   "alerts@example.com", None, None))
    return sent


def _cve(cve_id, severity="CRITICAL", kev=False, vendor="fortinet"):
    with get_session_factory()() as s:
        s.add(Cve(cve_id=cve_id, title=f"{vendor} bug", severity=severity, cvss_score=9.8 if severity == "CRITICAL" else 5.0,
                  kev=kev, provenance={}, cvss_metrics=[], products=[CveProduct(vendor=vendor, product="x", source="nvd")]))
        s.commit()


def test_alert_rule_validation(root):
    base = {"name": "Rule one", "criteria": {}, "channels": ["email"], "recipients": {"emails": ["a@b.co"]}}
    r = root.post("/api/alerts", json=base)
    assert r.status_code == 422 and "at least one criterion" in r.text
    r = root.post("/api/alerts", json={**base, "criteria": {"min_severity": "HIGH"}, "recipients": {}})
    assert r.status_code == 422 and "needs at least one recipient" in r.text
    r = root.post("/api/alerts", json={**base, "name": "Rule two", "criteria": {"kev_added": True}, "channels": ["slack"],
                                       "webhooks": {"slack": "https://evil.example.com/hook"}})
    assert r.status_code == 422 and "webhook rejected" in r.text


def test_alerts_match_throttle_and_deliver(root, alert_env, settings):
    r = root.post("/api/alerts", json={
        "name": "Critical Fortinet", "criteria": {"min_severity": "CRITICAL", "vendors": ["fortinet"]},
        "channels": ["email", "slack"], "recipients": {"emails": ["soc@acme.com"]},
        "webhooks": {"slack": "https://hooks.slack.com/services/T0/B0/xyz"}, "throttle_minutes": 60})
    assert r.status_code == 201 and r.json()["webhooks_set"] == ["slack"] and "hooks.slack.com" not in r.text
    rid = r.json()["id"]
    _cve("CVE-2026-1000")                      # match
    _cve("CVE-2026-1001", severity="MEDIUM")   # below severity
    _cve("CVE-2026-1002", vendor="cisco")      # not on watchlist
    res = root.post(f"/api/alerts/{rid}/run").json()
    assert res["new_matches"] == 1 and res["delivered"] == 1
    assert alert_env["emails"][0][1] == ["soc@acme.com"] and b"CVE-2026-1000" in alert_env["slack"][0]
    from exposurecatalyst.ingestion.service import tick  # scheduler path: no duplicate, throttled
    from tests.test_ingestion import FakeSource

    _cve("CVE-2026-1003")
    tick(settings, get_session_factory(), lambda n, s: FakeSource())
    with get_session_factory()() as s:
        ev = {e.cve_id: e.status for e in s.query(AlertEvent)}
    assert ev == {"CVE-2026-1000": "sent", "CVE-2026-1003": "pending"}  # throttled until the window passes
    assert len(alert_env["emails"]) == 1
    root.post(f"/api/alerts/{rid}/run")
    assert len(alert_env["emails"]) == 2
    assert [e["cve_id"] for e in root.get(f"/api/alerts/{rid}/events").json()] == ["CVE-2026-1003", "CVE-2026-1000"]


def test_custom_roles_crud(root):
    r = root.post("/api/admin/roles", json={"name": "Vuln Manager", "permissions": ["cve:view", "advisory:approve"]})
    assert r.status_code == 201
    rid = r.json()["id"]
    assert root.put(f"/api/admin/roles/{rid}", json={"name": "Vuln Manager", "permissions": ["cve:view"]}).json()["permissions"] == ["cve:view"]
    with get_session_factory()() as s:
        sys_id = s.query(Role).filter_by(name="Viewer").one().id
    assert root.delete(f"/api/admin/roles/{sys_id}").status_code == 409
    assert root.delete(f"/api/admin/roles/{rid}").status_code == 204


def test_unused(): assert PASSWORD and UserSession

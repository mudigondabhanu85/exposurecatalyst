"""Settings → SMTP delivery methods: Microsoft 365 OAuth2 (XOAUTH2) and the Amazon SES API."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs

import httpx
import pytest

from exposurecatalyst.advisories import delivery
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import AuditLog


@pytest.fixture
def admin(login, settings):
    settings.smtp_allow_private_hosts = True
    return login("Super Admin", username="mailroot")


@pytest.fixture(autouse=True)
def _fresh_tokens():
    delivery._token_cache.clear()
    yield
    delivery._token_cache.clear()
    delivery.M365_TRANSPORT = None


class FakeSMTP:
    log: dict = {}

    def __init__(self, host, port, timeout=None, context=None):
        FakeSMTP.log.setdefault("conns", []).append((host, port))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def starttls(self, context):
        FakeSMTP.log["tls"] = True

    def login(self, u, p):
        FakeSMTP.log["login"] = (u, p)

    def auth(self, mechanism, authobject, *, initial_response_ok=True):
        FakeSMTP.log.setdefault("auth", []).append((mechanism, authobject()))
        assert authobject(b'{"status":"401"}') == ""  # error challenge → empty response (RFC 7628)

    def send_message(self, msg, from_addr, to_addrs):
        FakeSMTP.log.setdefault("sent", []).append((msg, from_addr, to_addrs))


M365 = {"provider": "smtp", "auth": "oauth2_m365", "host": "localhost", "port": 587, "security": "starttls",
        "username": "secops@contoso.com", "m365_tenant_id": "contoso.onmicrosoft.com", "m365_client_id": "app-id",
        "m365_client_secret": "entra-secret-value", "from_address": "secops@contoso.com"}


def test_m365_oauth2_xoauth2_and_token_cache(admin, monkeypatch):
    FakeSMTP.log = {}
    token_calls = []

    def entra(req: httpx.Request):
        token_calls.append(req)
        assert req.url.host == "login.microsoftonline.com"
        assert req.url.path == "/contoso.onmicrosoft.com/oauth2/v2.0/token"
        form = parse_qs(req.content.decode())
        assert form["grant_type"] == ["client_credentials"] and form["client_secret"] == ["entra-secret-value"]
        assert form["scope"] == ["https://outlook.office365.com/.default"]
        return httpx.Response(200, json={"access_token": "eyJ.m365", "expires_in": 3599})

    delivery.M365_TRANSPORT = httpx.MockTransport(entra)
    monkeypatch.setattr(delivery.smtplib, "SMTP", FakeSMTP)
    r = admin.put("/api/settings/smtp", json=M365)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["auth"] == "oauth2_m365" and out["has_m365_client_secret"] and "entra-secret-value" not in r.text
    assert not out["has_password"]

    for _ in range(2):
        assert admin.post("/api/settings/smtp/test", json={"to": "me@contoso.com"}).json()["sent"]
    assert len(token_calls) == 1  # cached
    mech, initial = FakeSMTP.log["auth"][0]
    assert mech == "XOAUTH2" and initial == "user=secops@contoso.com\x01auth=Bearer eyJ.m365\x01\x01"
    assert FakeSMTP.log["tls"] and "login" not in FakeSMTP.log
    with get_session_factory()() as s:
        details = json.dumps([a.details for a in s.query(AuditLog).filter(AuditLog.action.like("settings.smtp%"))])
    assert "entra-secret-value" not in details and "client_secret_changed" in details

    # keep the stored secret when the field is omitted
    r = admin.put("/api/settings/smtp", json={k: v for k, v in M365.items() if k != "m365_client_secret"})
    assert r.json()["has_m365_client_secret"]


def test_m365_bad_credentials_reported(admin, monkeypatch):
    delivery.M365_TRANSPORT = httpx.MockTransport(
        lambda r: httpx.Response(200, json={"error": "invalid_client"}))
    monkeypatch.setattr(delivery.smtplib, "SMTP", FakeSMTP)
    admin.put("/api/settings/smtp", json=M365)
    r = admin.post("/api/settings/smtp/test", json={"to": "me@contoso.com"})
    assert r.status_code == 502 and "did not return an access token" in r.text


@pytest.mark.parametrize("patch,msg", [
    ({"m365_tenant_id": None}, "tenant"),
    ({"m365_client_id": ""}, "client"),
    ({"username": None}, "mailbox"),
    ({"security": "none"}, "STARTTLS"),
    ({"m365_tenant_id": "bad/tenant"}, "tenant"),
])
def test_m365_validation(admin, patch, msg):
    r = admin.put("/api/settings/smtp", json={**M365, **patch})
    assert r.status_code == 422 and msg in r.text


def test_m365_requires_secret_first_time(admin):
    r = admin.put("/api/settings/smtp", json={k: v for k, v in M365.items() if k != "m365_client_secret"})
    assert r.status_code == 422 and "client secret" in r.text


class FakeSes:
    def __init__(self):
        self.calls = []

    def send_email(self, **kw):
        self.calls.append(kw)
        return {"MessageId": f"0100-{len(self.calls)}"}


def test_ses_api_sends_raw_in_batches(admin, monkeypatch, login, settings):
    ses = FakeSes()
    regions = []
    monkeypatch.setattr(delivery, "_ses_client", lambda region: regions.append(region) or ses)
    r = admin.put("/api/settings/smtp", json={"provider": "ses_api", "ses_region": "eu-west-1",
                                              "ses_configuration_set": "excat-events",
                                              "from_address": "advisories@example.com", "host": "ignored.example"})
    assert r.status_code == 200, r.text
    assert r.json()["provider"] == "ses_api" and r.json()["host"] is None  # SMTP fields cleared
    res = admin.post("/api/settings/smtp/test", json={"to": "me@example.com"}).json()
    assert res["message_id"] == "<0100-1@email.amazonses.com>" and regions == ["eu-west-1"]
    call = ses.calls[0]
    assert call["FromEmailAddress"] == "advisories@example.com" and call["ConfigurationSetName"] == "excat-events"
    assert call["Destination"] == {"ToAddresses": ["me@example.com"]}
    assert b"Subject: ExposureCatalyst SMTP test" in call["Content"]["Raw"]["Data"]

    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"], msg["Bcc"] = "x", "hidden@example.com"
    msg.set_content("x")
    cfg = delivery.SmtpConfig(host="", port=0, security="", username=None, password=None,
                              from_address="a@example.com", from_name=None, reply_to=None,
                              provider="ses_api", ses_region="us-east-1")
    ses.calls.clear()
    delivery.send(msg, [f"u{i}@example.com" for i in range(120)], cfg, settings)
    assert [len(c["Destination"]["ToAddresses"]) for c in ses.calls] == [50, 50, 20]
    assert all(b"hidden@example.com" not in c["Content"]["Raw"]["Data"] for c in ses.calls)


@pytest.mark.parametrize("region", [None, "", "us-east", "../etc", "US-EAST-1"])
def test_ses_region_validated(admin, region):
    r = admin.put("/api/settings/smtp", json={"provider": "ses_api", "ses_region": region,
                                              "from_address": "a@example.com"})
    assert r.status_code == 422


def test_ses_gov_region_ok(admin, monkeypatch):
    assert admin.put("/api/settings/smtp", json={"provider": "ses_api", "ses_region": "us-gov-west-1",
                                                 "from_address": "a@example.com"}).status_code == 200


def test_presets_and_password_mode_unchanged(admin):
    ids = {p["id"] for p in admin.get("/api/settings/smtp/presets").json()}
    assert {"m365_oauth", "ses_api", "ses_smtp"} <= ids
    r = admin.put("/api/settings/smtp", json={"host": "localhost", "port": 587, "username": "u", "password": "pw",
                                              "from_address": "a@example.com"})
    assert r.status_code == 200 and r.json()["provider"] == "smtp" and r.json()["auth"] == "password"


def test_xoauth2_wire_format():
    initial = delivery.xoauth2("a@b.c", "tok")()
    assert base64.b64encode(initial.encode()).decode() == base64.b64encode(b"user=a@b.c\x01auth=Bearer tok\x01\x01").decode()

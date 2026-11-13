from __future__ import annotations

import email
import io
from datetime import UTC, datetime
from email import policy

import pytest
from openpyxl import load_workbook

from exposurecatalyst.advisories import delivery
from exposurecatalyst.advisories.render import TemplateValidationError, validate_template
from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import AdvisoryDelivery, AuditLog, Cve, CveProduct


@pytest.fixture
def cve(app):
    with get_session_factory()() as s:
        s.add(Cve(cve_id="CVE-2024-21762", title="Fortinet FortiOS Out-of-Bound Write", description="OOB write.\nLine 2",
                  severity="CRITICAL", cvss_score=9.8, cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N",
                  epss_score=0.94, epss_percentile=0.999, kev=True, exploit_available=True, provenance={},
                  cvss_metrics=[], patch_refs=["https://fortiguard.com/psirt/FG-IR-24-015"],
                  kev_required_action="Apply mitigations per vendor instructions.",
                  products=[CveProduct(vendor="fortinet", product="fortios", source="nvd")]))
        s.commit()


@pytest.fixture
def analyst(login):
    return login("Security Analyst", username="ana")


@pytest.fixture
def approver(login):
    return login("Approver", username="apu")


def _new(c, cve_id="CVE-2024-21762"):
    r = c.post("/api/advisories", json={"cve_id": cve_id})
    assert r.status_code == 201, r.text
    return r.json()


def _approved(analyst, approver, **extra):
    adv = _new(analyst)
    analyst.patch(f"/api/advisories/{adv['id']}", json={"to_addrs": ["Ops@Example.com"], "bcc_addrs": ["audit@example.com"],
                                                       **extra})
    analyst.post(f"/api/advisories/{adv['id']}/assets", json={"source": "Qualys", "hostname": "web01.corp",
                                                             "ip_address": "10.0.0.5", "source_ref": "QID-12345"})
    assert analyst.post(f"/api/advisories/{adv['id']}/submit").status_code == 200
    r = approver.post(f"/api/advisories/{adv['id']}/approve", json={"comment": "LGTM"})
    assert r.status_code == 200, r.text
    return r.json()


def test_create_prefills_from_cve(analyst, cve):
    a = _new(analyst)
    year = datetime.now(UTC).year
    assert a["advisory_id"] == f"EXCAT-{year}-0001" and a["status"] == "draft"
    assert a["template_name"] == "Critical" and a["severity"] == "CRITICAL"
    assert a["subject"] == f"[CRITICAL] EXCAT-{year}-0001 Security Advisory: CVE-2024-21762 – Fortinet Fortios – 0 assets affected"
    assert [r["validated"] for r in a["matrix"]] == ["Not Integrated"] * 6
    assert "Apply mitigations" in a["remediation"]
    assert _new(analyst)["advisory_id"] == f"EXCAT-{year}-0002"
    assert analyst.post("/api/advisories", json={"cve_id": "CVE-2099-0001"}).status_code == 404


def test_matrix_validated_yes_only_when_assets_found_and_dedup(analyst, cve):
    a = _new(analyst)
    base = f"/api/advisories/{a['id']}"
    analyst.post(f"{base}/assets", json={"source": "Qualys", "hostname": "WEB01.corp.", "ip_address": "10.0.0.5"})
    analyst.post(f"{base}/assets", json={"source": "Wiz", "ip_address": "10.0.0.5", "resource_id": "i-0abc"})
    analyst.post(f"{base}/assets", json={"source": "Wiz", "resource_id": "I-0ABC", "owner": "team-a"})
    analyst.post(f"{base}/assets", json={"source": "Wiz", "hostname": "db02"})
    r = analyst.put(f"{base}/sources/Tanium", json={"manual_count": 0}).json()
    m = {row["source"]: row for row in r["matrix"]}
    assert m["Qualys"]["validated"] == "Yes" and m["Qualys"]["manual"]
    assert m["Wiz"]["validated"] == "Yes" and m["Wiz"]["asset_count"] == 3
    assert m["Tanium"]["validated"] == "No"
    assert m["Zafran"]["validated"] == "Not Integrated"
    assert r["total_unique_assets"] == 2  # web01 ≡ 10.0.0.5 ≡ i-0abc ; db02
    r = analyst.put(f"{base}/sources/ArmorCode", json={"manual_count": 4}).json()
    assert r["total_unique_assets"] == 6
    assert analyst.post(f"{base}/assets", json={"source": "Qualys", "owner": "x"}).status_code == 422


def test_workflow_and_segregation_of_duties(analyst, approver, login, cve):
    a = _new(analyst)
    base = f"/api/advisories/{a['id']}"
    assert analyst.post(f"{base}/submit").status_code == 422  # no recipients
    assert analyst.patch(base, json={"to_addrs": ["not-an-email"]}).status_code == 422
    analyst.patch(base, json={"to_addrs": ["ops@example.com"], "subject": "Hi\r\nBcc: evil@example.com x"})
    assert "\n" not in analyst.get(base).json()["subject"]
    assert analyst.post(f"{base}/submit").json()["status"] == "in_review"
    assert analyst.patch(base, json={"summary": "x"}).status_code == 409  # locked while in review
    assert analyst.post(f"{base}/approve", json={}).status_code == 403  # analyst lacks advisory:approve
    assert approver.post(f"{base}/reject", json={}).status_code == 422  # reason required
    assert approver.post(f"{base}/reject", json={"comment": "add impact"}).json()["status"] == "draft"
    analyst.post(f"{base}/submit")
    assert approver.post(f"{base}/approve", json={}).json()["status"] == "approved"

    both = login("Security Analyst", "Approver", username="dual")
    b = _new(both)
    both.patch(f"/api/advisories/{b['id']}", json={"to_addrs": ["ops@example.com"]})
    both.post(f"/api/advisories/{b['id']}/submit")
    r = both.post(f"/api/advisories/{b['id']}/approve", json={})
    assert r.status_code == 409 and "segregation of duties" in r.json()["detail"]


def test_exports_require_approval(analyst, approver, cve):
    a = _new(analyst)
    for fmt in ("eml", "html", "pdf", "xlsx", "clipboard"):
        assert analyst.get(f"/api/advisories/{a['id']}/export/{fmt}").status_code == 409
    assert approver.get(f"/api/advisories/{a['id']}/export/eml").status_code == 409


def test_eml_is_outlook_draft_with_cid_logo_and_excel(analyst, approver, cve):
    a = _approved(analyst, approver)
    r = analyst.get(f"/api/advisories/{a['id']}/export/eml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("message/rfc822")
    assert f'{a["advisory_id"]}_CVE-2024-21762.eml' in r.headers["content-disposition"]
    msg = email.message_from_bytes(r.content, policy=policy.default)
    assert msg["X-Unsent"] == "1" and msg["Bcc"] == "audit@example.com" and msg["Date"] is None
    html = msg.get_body(("html",)).get_content()
    assert 'src="cid:excat-logo"' in html and 'alt="ExposureCatalyst"' in html and "<svg" not in html
    assert "Generated by ExposureCatalyst" in html and a["advisory_id"] in html
    images = [p for p in msg.walk() if p.get_content_type() == "image/png"]
    assert len(images) == 1 and images[0]["Content-ID"] == "<excat-logo>"
    att = next(msg.iter_attachments())
    assert att.get_filename() == f"{a['advisory_id']}_CVE-2024-21762_affected_assets.xlsx"
    assert "Not Integrated" in msg.get_body(("plain",)).get_content()


def test_html_pdf_clipboard_use_data_uri(analyst, approver, cve):
    a = _approved(analyst, approver)
    for fmt in ("html", "clipboard"):
        body = analyst.get(f"/api/advisories/{a['id']}/export/{fmt}").text
        assert 'src="data:image/png;base64,' in body and "cid:" not in body
    pdf = analyst.get(f"/api/advisories/{a['id']}/export/pdf")
    assert pdf.content.startswith(b"%PDF")
    with get_session_factory()() as s:
        assert {d.channel for d in s.query(AdvisoryDelivery)} == {"html", "clipboard", "pdf"}


def test_excel_branding_dedup_and_formula_injection(analyst, approver, cve):
    a = _new(analyst)
    base = f"/api/advisories/{a['id']}"
    analyst.post(f"{base}/assets", json={"source": "Qualys", "hostname": "=HYPERLINK(\"http://evil\")", "owner": "+cmd"})
    analyst.post(f"{base}/assets", json={"source": "Wiz", "hostname": "web01", "resource_id": "i-1"})
    analyst.patch(base, json={"to_addrs": ["ops@example.com"]})
    analyst.post(f"{base}/submit")
    approver.post(f"{base}/approve", json={})
    wb = load_workbook(io.BytesIO(analyst.get(f"{base}/export/xlsx").content))
    assert wb.sheetnames == ["Summary", "All Assets (Deduplicated)", "Qualys", "Wiz"]
    summary = wb["Summary"]
    assert len(summary._images) == 1
    header = summary["A4"]
    assert header.value == "Field" and header.fill.fgColor.rgb.endswith("0B1B33") and header.font.bold
    assert header.font.color.rgb.endswith("FFFFFF")
    q = wb["Qualys"]
    assert q.freeze_panes == "A2" and q["A2"].value.startswith("'=") and q["A2"].data_type == "s"
    assert q["F2"].value == "'+cmd" and q["L2"].value == "Manual"
    assert q.column_dimensions["A"].width > 10


def test_send_via_smtp(analyst, approver, login, cve, settings, monkeypatch):
    a = _approved(analyst, approver)
    sender = analyst
    assert sender.post(f"/api/advisories/{a['id']}/send", json={"confirm": True}).status_code == 409  # no SMTP yet

    admin = login("Super Admin", username="root")
    settings.smtp_allow_private_hosts = True
    settings.smtp_allowed_ports = "25,465,587,1025"
    assert admin.put("/api/settings/smtp", json={"host": "169.254.169.254", "port": 587, "from_address": "a@b.co"}).status_code == 422
    assert admin.put("/api/settings/smtp", json={"host": "localhost", "port": 2526, "from_address": "a@b.co"}).status_code == 422
    r = admin.put("/api/settings/smtp", json={"host": "localhost", "port": 587, "security": "starttls", "username": "u",
                                              "password": "s3cret", "from_address": "secops@example.com",
                                              "reply_to": "soc@example.com"})
    assert r.status_code == 200 and r.json()["has_password"] and "s3cret" not in r.text

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["conn"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def starttls(self, context):
            sent["tls"] = True

        def login(self, u, p):
            sent["auth"] = (u, p)

        def send_message(self, msg, from_addr, to_addrs):
            sent.update(msg=msg, from_addr=from_addr, to=to_addrs)

    monkeypatch.setattr(delivery.smtplib, "SMTP", FakeSMTP)
    assert sender.post(f"/api/advisories/{a['id']}/send", json={"confirm": False}).status_code == 422
    r = sender.post(f"/api/advisories/{a['id']}/send", json={"confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "sent"
    assert sent["tls"] and sent["auth"] == ("u", "s3cret")
    assert sent["to"] == ["ops@example.com", "audit@example.com"] and sent["msg"]["Bcc"] is None
    assert sent["msg"]["X-Unsent"] is None and sent["msg"]["Reply-To"] == "soc@example.com"
    assert sender.post(f"/api/advisories/{a['id']}/send", json={"confirm": True}).status_code == 409  # no double send
    with get_session_factory()() as s:
        entry = s.query(AuditLog).filter_by(action="advisory.sent").one()
        assert entry.actor_username == "ana" and entry.details["bcc"] == ["audit@example.com"]
    hist = sender.get(f"/api/advisories/{a['id']}/history").json()
    assert [h["action"] for h in hist][-1] == "advisory.sent"


def test_preview_is_sandboxed_and_watermarked(analyst, cve):
    a = _new(analyst)
    r = analyst.get(f"/api/advisories/{a['id']}/preview")
    assert "sandbox" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "SAMEORIGIN"
    assert "NOT APPROVED" in r.text and "OOB write.<br />" in r.text


def test_upload_csv(analyst, cve):
    a = _new(analyst)
    csv_data = (b"Hostname,IP Address,Source,QID,Detection Date\nweb01,10.0.0.1,Qualys,QID-1,2026-11-01\n"
                b",,Qualys,QID-2,\nweb02,,,,\n")
    r = analyst.post(f"/api/advisories/{a['id']}/assets/upload", files={"file": ("assets.csv", csv_data, "text/csv")},
                     data={"default_source": "Tanium"})
    body = r.json()
    assert r.status_code == 200 and body["imported"] == 2 and len(body["errors"]) == 1
    srcs = {x["source"] for x in body["advisory"]["assets"]}
    assert srcs == {"Qualys", "Tanium"} and all(x["is_manual"] for x in body["advisory"]["assets"])
    bad = analyst.post(f"/api/advisories/{a['id']}/assets/upload", files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert bad.status_code == 422


@pytest.mark.parametrize("body", [
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "{% for x in range(10) %}{{ x }",
])
def test_template_sandbox_blocks_ssti(body):
    with pytest.raises(TemplateValidationError):
        validate_template("Subject {{ advisory.cve_id }}", body)


def test_template_versioning_and_sod(login, approver, cve):
    author = login("Admin", username="tpladmin")  # Admin holds template:manage
    tpls = author.get("/api/templates").json()
    assert {t["name"] for t in tpls} == {"Critical", "High", "Informational", "Executive"}
    crit = next(t for t in tpls if t["kind"] == "critical")
    r = author.post(f"/api/templates/{crit['id']}/versions",
                    json={"subject_template": "[{{ advisory.severity }}] {{ advisory.advisory_id }} {{ advisory.cve_id }}",
                          "body_template": "<p>{{ advisory.summary }}</p>{{ components.validation_matrix }}"})
    v2 = r.json()["versions"][-1]
    assert r.status_code == 201 and v2["version"] == 2 and v2["status"] == "draft"
    assert approver.post(f"/api/template-versions/{v2['id']}/approve").status_code == 409  # not submitted yet
    author.post(f"/api/template-versions/{v2['id']}/submit")
    t = approver.post(f"/api/template-versions/{v2['id']}/approve").json()
    assert [v["status"] for v in t["versions"]] == ["retired", "approved"]

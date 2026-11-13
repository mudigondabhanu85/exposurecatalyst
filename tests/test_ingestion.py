from __future__ import annotations

import gzip
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from exposurecatalyst.ingestion.epss import EpssSource
from exposurecatalyst.ingestion.http import RateLimiter, SourceClient, SourceHTTPError
from exposurecatalyst.ingestion.kev import KevSource
from exposurecatalyst.ingestion.normalize import parse_nvd_cve, split_cpe
from exposurecatalyst.ingestion.nvd import NvdSource, windows
from exposurecatalyst.ingestion.service import claim, due_sources, run_source, tick
from exposurecatalyst.models import Cve, CveEvent, JobRun, SourceState
from tests.conftest import load_fixture

NOOP_SLEEP = lambda _s: None  # noqa: E731


def kev_catalog(extra: list[dict] | None = None, n_filler: int = 120) -> dict:
    vulns = [{"cveID": f"CVE-2020-{10000 + i}", "vendorProject": "Acme", "product": "Widget",
              "vulnerabilityName": f"Acme Widget bug {i}", "dateAdded": "2024-01-01",
              "shortDescription": "x", "requiredAction": "Patch", "dueDate": "2024-01-22",
              "knownRansomwareCampaignUse": "Unknown"} for i in range(n_filler)]
    return {"catalogVersion": "2024.03.01", "vulnerabilities": vulns + (extra or [])}


# --- normalization -----------------------------------------------------------------------------

def test_parse_nvd_normalizes_and_sanitizes():
    item = load_fixture("nvd_page.json")["vulnerabilities"][0]
    n = parse_nvd_cve(item)
    assert n.cve_id == "CVE-2024-21762"
    assert n.published_at.tzinfo is not None
    assert {m["version"] for m in n.cvss_metrics} == {"3.1", "4.0"}
    primary = n.primary_cvss(["3.1", "4.0", "3.0", "2.0"])
    assert primary["score"] == 9.8 and primary["type"] == "Primary"
    assert n.primary_cvss(["4.0", "3.1"])["version"] == "4.0"
    assert n.cwes == ["CWE-787"]
    assert all(r["url"].startswith("https://") for r in n.references)  # javascript: dropped
    assert n.exploit_refs == ["https://example.org/poc/CVE-2024-21762"]
    assert n.patch_refs == ["https://fortiguard.com/psirt/FG-IR-24-015"]
    assert {(p.vendor, p.product) for p in n.products} == {("fortinet", "fortios")}
    assert len(n.products) == 2


def test_split_cpe_handles_escapes():
    assert split_cpe(r"cpe:2.3:a:vendor:prod\:uct:1.0")[4] == "prod:uct"


def test_nvd_windows_respect_120_day_limit():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    ws = list(windows(start, start + timedelta(days=300)))
    assert len(ws) == 3 and all(b - a <= timedelta(days=120) for a, b in ws)


# --- NVD source --------------------------------------------------------------------------------

def test_nvd_run_creates_records_with_provenance_and_timeline(settings, db):
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(200, json=load_fixture("nvd_page.json"))

    src = NvdSource(settings, transport=httpx.MockTransport(handler), sleep=NOOP_SLEEP)
    state = db.get(SourceState, "nvd")
    res = src.run(db, state, datetime.now(UTC))
    assert res.records == 2 and res.detail["created"] == 2
    assert "lastModStartDate" in calls[0].url.params and calls[0].url.params["resultsPerPage"] == "2000"
    assert "apiKey" not in calls[0].headers

    cve = db.scalar(select(Cve).where(Cve.cve_id == "CVE-2024-21762"))
    assert cve.severity == "CRITICAL" and cve.cvss_score == 9.8 and cve.cvss_version == "3.1"
    assert cve.exploit_available is True
    assert cve.title == "Fortinet FortiOS Out-of-Bound Write Vulnerability"
    assert cve.provenance["cvss"]["source"] == "nvd"
    assert [e.event_type for e in cve.events] == ["PUBLISHED"]
    assert state.cursor_at is not None

    unscored = db.scalar(select(Cve).where(Cve.cve_id == "CVE-2024-0001"))
    assert unscored.severity == "UNKNOWN" and unscored.cvss_score is None

    # Same payload again → no duplicate records, no spurious MODIFIED events.
    src.run(db, state, datetime.now(UTC))
    assert db.query(Cve).count() == 2
    assert db.query(CveEvent).filter_by(event_type="MODIFIED").count() == 0


def test_nvd_paginates(settings, db):
    page = load_fixture("nvd_page.json")
    v = page["vulnerabilities"]

    def handler(req):
        idx = int(req.url.params["startIndex"])
        return httpx.Response(200, json={**page, "totalResults": 2, "vulnerabilities": [v[idx]]})

    src = NvdSource(settings, transport=httpx.MockTransport(handler), sleep=NOOP_SLEEP)
    assert src.run(db, db.get(SourceState, "nvd"), datetime.now(UTC)).records == 2


# --- KEV ---------------------------------------------------------------------------------------

def test_kev_flags_existing_and_creates_stub(settings, db):
    db.add(Cve(cve_id="CVE-2024-21762", severity="CRITICAL", provenance={}, cvss_metrics=[]))
    db.commit()
    extra = [{"cveID": "CVE-2024-21762", "vendorProject": "Fortinet", "product": "FortiOS",
              "vulnerabilityName": "Fortinet FortiOS OOB Write", "dateAdded": "2024-02-09",
              "shortDescription": "OOB write", "requiredAction": "Apply updates", "dueDate": "2024-02-16",
              "knownRansomwareCampaignUse": "Known"}]
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=kev_catalog(extra), headers={"ETag": '"v1"'}))
    src = KevSource(settings, transport=transport, sleep=NOOP_SLEEP)
    state = db.get(SourceState, "kev")
    res = src.run(db, state, datetime.now(UTC))
    assert res.detail["added"] == 121
    cve = db.scalar(select(Cve).where(Cve.cve_id == "CVE-2024-21762"))
    assert cve.kev and cve.exploit_available and str(cve.kev_due_date) == "2024-02-16"
    assert cve.kev_ransomware_use == "Known"
    assert any(e.event_type == "KEV_ADDED" for e in cve.events)
    stub = db.scalar(select(Cve).where(Cve.cve_id == "CVE-2020-10000"))
    assert stub.products[0].vendor == "Acme" and stub.provenance["description"]["source"] == "kev"
    assert state.meta["etag"] == '"v1"'


def test_kev_304_and_sanity_guard(settings, db):
    state = db.get(SourceState, "kev")
    state.meta = {"etag": '"v1"'}
    seen = {}

    def handler(r):
        seen["inm"] = r.headers.get("if-none-match")
        return httpx.Response(304)

    assert KevSource(settings, transport=httpx.MockTransport(handler), sleep=NOOP_SLEEP).run(
        db, state, datetime.now(UTC)).detail == {"unchanged": True}
    assert seen["inm"] == '"v1"'

    tiny = httpx.MockTransport(lambda r: httpx.Response(200, json=kev_catalog(n_filler=3)))
    with pytest.raises(SourceHTTPError):
        KevSource(settings, transport=tiny, sleep=NOOP_SLEEP).run(db, db.get(SourceState, "kev"), datetime.now(UTC))


# --- EPSS --------------------------------------------------------------------------------------

def test_epss_api_mode(settings, db):
    db.add_all([Cve(cve_id="CVE-2024-21762", provenance={}, cvss_metrics=[]),
                Cve(cve_id="CVE-2024-0001", provenance={}, cvss_metrics=[])])
    db.commit()
    body = {"data": [{"cve": "CVE-2024-21762", "epss": "0.94321", "percentile": "0.99912", "date": "2024-03-01"}]}
    src = EpssSource(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body)),
                     sleep=NOOP_SLEEP)
    res = src.run(db, db.get(SourceState, "epss"), datetime.now(UTC))
    assert res.records == 1 and res.detail["mode"] == "api"
    cve = db.scalar(select(Cve).where(Cve.cve_id == "CVE-2024-21762"))
    assert cve.epss_score == pytest.approx(0.94321) and str(cve.epss_date) == "2024-03-01"
    other = db.scalar(select(Cve).where(Cve.cve_id == "CVE-2024-0001"))
    assert other.epss_score is None and other.epss_checked_at is not None  # not re-asked hourly
    assert src.run(db, db.get(SourceState, "epss"), datetime.now(UTC)).detail["mode"] == "noop"


def test_epss_bulk_mode(settings, db):
    settings.epss_bulk_threshold = 100
    db.add_all([Cve(cve_id=f"CVE-2023-{1000 + i}", provenance={}, cvss_metrics=[]) for i in range(150)])
    db.commit()
    csv_text = "#model_version:v2025.03.14,score_date:2025-06-01T00:00:00+0000\ncve,epss,percentile\n"
    csv_text += "".join(f"CVE-2023-{1000 + i},0.{i:05d},0.5\n" for i in range(150))
    csv_text += "CVE-1999-0001,0.1,0.1\n"
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=gzip.compress(csv_text.encode())))
    res = EpssSource(settings, transport=transport, sleep=NOOP_SLEEP).run(db, db.get(SourceState, "epss"),
                                                                          datetime.now(UTC))
    assert res.detail["mode"] == "bulk" and res.records == 150
    assert str(db.scalar(select(Cve).where(Cve.cve_id == "CVE-2023-1001")).epss_date) == "2025-06-01"


# --- HTTP client -------------------------------------------------------------------------------

def test_http_retries_on_429_with_retry_after(settings):
    attempts, sleeps = [], []

    def handler(r):
        attempts.append(1)
        return httpx.Response(429, headers={"Retry-After": "7"}) if len(attempts) < 2 else httpx.Response(200)

    c = SourceClient("t", settings, rate=100, per=1, transport=httpx.MockTransport(handler), sleep=sleeps.append)
    assert c.get("https://api.first.org/x").status_code == 200
    assert sleeps == [7.0]


def test_http_gives_up_and_does_not_retry_4xx(settings):
    c = SourceClient("t", settings, rate=100, per=1, sleep=NOOP_SLEEP,
                     transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(SourceHTTPError, match="giving up after 3"):
        c.get("https://api.first.org/x")
    calls = []
    c2 = SourceClient("t", settings, rate=100, per=1, sleep=NOOP_SLEEP,
                      transport=httpx.MockTransport(lambda r: calls.append(1) or httpx.Response(403)))
    with pytest.raises(SourceHTTPError, match="HTTP 403"):
        c2.get("https://api.first.org/x")
    assert len(calls) == 1


def test_http_blocks_non_allowlisted_host(settings):
    c = SourceClient("t", settings, rate=1, per=1, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(ValueError, match="allowlist"):
        c.get("https://evil.example.com/")


def test_rate_limiter_waits_when_empty():
    t = [0.0]
    slept = []
    lim = RateLimiter(2, 1.0, clock=lambda: t[0], sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s)))
    for _ in range(3):
        lim.acquire()
    assert slept and slept[0] == pytest.approx(0.5)


# --- orchestration -----------------------------------------------------------------------------

class FakeSource:
    name = "kev"

    def __init__(self, fail=False):
        self.fail = fail

    def run(self, db, state, now):
        if self.fail:
            raise RuntimeError("upstream exploded")
        from exposurecatalyst.ingestion.base import RunResult

        return RunResult(3)

    def close(self):
        pass


def test_run_source_records_health_and_lock(settings, db_factory):
    job = run_source("kev", "manual", settings, db_factory, lambda n, s: FakeSource())
    assert job.status == "ok" and job.records == 3
    job = run_source("kev", "manual", settings, db_factory, lambda n, s: FakeSource(fail=True))
    assert job.status == "error" and "upstream exploded" in job.error
    with db_factory() as db:
        st = db.get(SourceState, "kev")
        assert st.status == "error" and st.consecutive_failures == 1
        assert db.query(JobRun).count() == 2
        assert claim(db, "kev", settings) is True
        assert claim(db, "kev", settings) is False  # second claimant loses


def test_due_sources_and_manual_refresh(settings, db_factory):
    ran = []
    factory = lambda n, s: (ran.append(n), FakeSource())[1]  # noqa: E731
    assert tick(settings, db_factory, factory) == ["nvd", "kev", "epss", "news"]
    with db_factory() as db:
        assert due_sources(db, settings) == []
        db.get(SourceState, "epss").refresh_requested_at = datetime.now(UTC)
        db.commit()
        assert due_sources(db, settings) == ["epss"]
    tick(settings, db_factory, factory)
    with db_factory() as db:
        assert db.query(JobRun).filter_by(trigger="manual").count() == 1


def test_http_follows_safe_relative_redirect_and_blocks_unsafe(settings):
    def handler(r):
        if r.url.path == "/current.csv.gz":
            return httpx.Response(302, headers={"Location": "dated-2026-11-13.csv.gz"})
        if r.url.path == "/dated-2026-11-13.csv.gz":
            return httpx.Response(200, content=b"ok")
        if r.url.path == "/evil":
            return httpx.Response(302, headers={"Location": "https://169.254.169.254/latest/meta-data/"})
        return httpx.Response(404)

    c = SourceClient("t", settings, rate=100, per=1, transport=httpx.MockTransport(handler), sleep=NOOP_SLEEP)
    r = c.get("https://epss.empiricalsecurity.com/current.csv.gz")
    assert r.status_code == 200 and str(r.request.url).endswith("/dated-2026-11-13.csv.gz")
    with pytest.raises(ValueError):  # UnsafeURLError: redirect target re-validated
        c.get("https://epss.empiricalsecurity.com/evil")

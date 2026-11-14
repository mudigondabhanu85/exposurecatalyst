"""Qualys VMDR.

1. CVE → QIDs: the KnowledgeBase API has no CVE filter, so the connector keeps an incremental CVE→QID map
   (``integration_vuln_map``) refreshed from ``/api/2.0/fo/knowledge_base/vuln/?action=list`` using
   ``last_modified_after`` (first sync bounded by ``kb_lookback_days``).
2. QIDs → hosts: Host List Detection ``/api/2.0/fo/asset/host/vm/detection/?action=list&qids=…`` with
   ``truncation_limit`` pagination (follows the ``WARNING/URL`` next-page link on the same host).
Rate limits: Qualys enforces per-subscription limits (default ~300 calls/hour, concurrency 2).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from defusedxml import ElementTree as ET  # noqa: N817 - hardened XML parsing (XXE/billion laughs)
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from exposurecatalyst.connectors.base import ConfigField, Connector, ConnectorError, ConnectorSpec, register
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import IntegrationVulnMap

KB_PATH = "/api/2.0/fo/knowledge_base/vuln/"
DETECTION_PATH = "/api/2.0/fo/asset/host/vm/detection/"
KB_REFRESH = timedelta(hours=24)
QID_BATCH = 200


def _text(el, path: str) -> str | None:
    found = el.find(path)
    return found.text.strip() if found is not None and found.text else None


@register
class QualysConnector(Connector):
    spec = ConnectorSpec(
        kind="qualys",
        label="Qualys",
        vendor="Qualys VMDR",
        description="Vulnerable hosts from Qualys VM/VMDR host detections (QIDs mapped from CVEs).",
        host_patterns=(
            "*.qualys.com",
            "*.qualys.eu",
            "*.qualys.ca",
            "*.qualys.in",
            "*.qualys.ae",
            "*.qualys.co.uk",
            "*.qualysksa.com",
        ),
        base_url_example="https://qualysapi.qg2.apps.qualys.com",
        fields=(
            ConfigField("username", "API username", required=True, help="Dedicated API user (see guide)"),
            ConfigField("password", "API password", kind="secret", required=True),
            ConfigField(
                "detection_status",
                "Detection statuses",
                default="New,Active,Re-Opened",
                help="Comma-separated Qualys detection statuses counted as affected",
            ),
            ConfigField(
                "kb_lookback_days",
                "Initial KnowledgeBase window (days)",
                kind="number",
                default=1825,
                help="First CVE→QID sync covers QIDs modified in this window",
            ),
        ),
        default_field_map={
            "hostname": "DNS",
            "ip_address": "IP",
            "os": "OS",
            "resource_id": "CLOUD_RESOURCE_ID",
            "cloud_account": "CLOUD_ACCOUNT_ID",
            "detection_date": "FIRST_FOUND_DATETIME",
            "source_ref": "QID_REF",
        },
        prerequisites=(
            "Qualys API access enabled for the subscription",
            "User with the Reader role (or a custom role) with API access and VM/VMDR module",
            "Asset groups / scope covering the assets you want correlated",
            "Your platform's API URL (Help → About → Qualys API Server)",
        ),
        docs="integrations/qualys/",
        rate=(300, 3600.0),
    )

    def __init__(self, *a, db: Session | None = None, **kw):
        super().__init__(*a, **kw)
        self.db = db
        # Qualys answers HTTP 409 when the subscription's concurrency limit is reached: back off and retry.
        self.client.retry_status.add(409)

    def _get(self, path_or_url: str, params: dict | None = None):
        url = path_or_url if path_or_url.startswith("https://") else self.url(path_or_url)
        if urlsplit(url).hostname != urlsplit(self.base_url).hostname:
            raise ConnectorError("Qualys pagination link points to a different host")
        resp = self.client.request(
            "GET",
            url,
            params=params,
            headers={"X-Requested-With": "ExposureCatalyst"},
            auth=(self.config["username"], self.secrets.get("password", "")),
        )
        root = ET.fromstring(resp.content)
        err = root.find(".//RESPONSE/CODE")
        if err is not None and root.tag == "SIMPLE_RETURN":
            raise ConnectorError(f"Qualys error {err.text}: {_text(root, './/RESPONSE/TEXT')}")
        return root

    def test_connection(self) -> str:
        root = self._get("/msp/about.php")
        version = _text(root, ".//WEB-VERSION") or _text(root, ".//QWEB-VERSION") or "unknown"
        return f"Connected to Qualys (web version {version})"

    # ---- CVE → QID map ------------------------------------------------------------------------
    def sync_kb(self) -> int:
        if self.db is None:
            raise ConnectorError("KnowledgeBase sync requires a database session")
        state = dict(self.integration.state or {})
        last = state.get("kb_synced_at")
        if last and as_utc(datetime.fromisoformat(last)) > utcnow() - KB_REFRESH:
            return 0
        since = last or (utcnow() - timedelta(days=int(self.config.get("kb_lookback_days") or 1825))).isoformat()
        root = self._get(
            KB_PATH,
            params={
                "action": "list",
                "details": "Basic",
                "show_disabled_flag": "0",
                "last_modified_after": since[:19] + "Z",
            },
        )
        added = 0
        for vuln in root.iter("VULN"):
            qid = _text(vuln, "QID")
            cves = [c.text.strip().upper() for c in vuln.iterfind("CVE_LIST/CVE/ID") if c.text]
            if not qid:
                continue
            self.db.execute(
                delete(IntegrationVulnMap).where(
                    IntegrationVulnMap.integration_id == self.integration.id, IntegrationVulnMap.external_id == qid
                )
            )
            for cve in set(cves):
                self.db.add(IntegrationVulnMap(integration_id=self.integration.id, cve_id=cve, external_id=qid))
                added += 1
        state["kb_synced_at"] = utcnow().isoformat()
        self.integration.state = state
        self.db.flush()
        return added

    def qids_for(self, cve_id: str) -> list[str]:
        self.sync_kb()
        return sorted(
            self.db.scalars(
                select(IntegrationVulnMap.external_id).where(
                    IntegrationVulnMap.integration_id == self.integration.id, IntegrationVulnMap.cve_id == cve_id
                )
            )
        )

    # ---- detections ---------------------------------------------------------------------------
    def iter_findings(self, cve_id: str) -> Iterator[dict[str, Any]]:
        qids = self.qids_for(cve_id)
        for i in range(0, len(qids), QID_BATCH):
            params: dict | None = {
                "action": "list",
                "qids": ",".join(qids[i : i + QID_BATCH]),
                "status": self.config.get("detection_status") or "New,Active,Re-Opened",
                "show_results": "0",
                "truncation_limit": "1000",
            }
            url = DETECTION_PATH
            while url:
                root = self._get(url, params)
                for host in root.iter("HOST"):
                    base = {k: _text(host, k) for k in ("ID", "IP", "DNS", "OS", "NETBIOS")}
                    base["DNS"] = base["DNS"] or _text(host, "DNS_DATA/HOSTNAME") or base["NETBIOS"]
                    base["CLOUD_RESOURCE_ID"] = _text(host, "CLOUD_RESOURCE_ID") or _text(host, "EC2_INSTANCE_ID")
                    base["CLOUD_ACCOUNT_ID"] = _text(host, "CLOUD_ACCOUNT_ID")
                    for det in host.iterfind("DETECTION_LIST/DETECTION"):
                        yield {
                            **base,
                            "QID": _text(det, "QID"),
                            "QID_REF": f"QID-{_text(det, 'QID')}",
                            "FIRST_FOUND_DATETIME": _text(det, "FIRST_FOUND_DATETIME"),
                            "STATUS": _text(det, "STATUS"),
                        }
                nxt = root.find(".//WARNING/URL")
                url, params = (nxt.text.strip(), None) if nxt is not None and nxt.text else (None, None)

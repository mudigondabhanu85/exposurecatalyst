"""Normalization of source payloads into the canonical CVE model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
PATCH_TAGS = {"Patch", "Vendor Advisory", "Mitigation", "Release Notes"}


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_date(value: str | None) -> date | None:
    return date.fromisoformat(value[:10]) if value else None


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def split_cpe(cpe: str) -> list[str]:
    """Split a CPE 2.3 formatted string on unescaped colons."""
    parts, buf, escaped = [], [], False
    for ch in cpe:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


@dataclass
class ProductRef:
    vendor: str
    product: str
    cpe: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    vulnerable: bool = True


@dataclass
class NormalizedCve:
    cve_id: str
    description: str | None
    vuln_status: str | None
    published_at: datetime | None
    last_modified_at: datetime | None
    cvss_metrics: list[dict[str, Any]] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    products: list[ProductRef] = field(default_factory=list)
    kev_name: str | None = None

    def primary_cvss(self, order: list[str]) -> dict[str, Any] | None:
        rank = {v: i for i, v in enumerate(order)}
        candidates = [m for m in self.cvss_metrics if m.get("score") is not None and m["version"] in rank]
        if not candidates:
            return None
        # Prefer configured version order, then the NVD "Primary" assessment, then the highest score.
        return sorted(candidates, key=lambda m: (rank[m["version"]], m.get("type") != "Primary", -m["score"]))[0]

    @property
    def exploit_refs(self) -> list[str]:
        return [r["url"] for r in self.references if "Exploit" in r.get("tags", [])]

    @property
    def patch_refs(self) -> list[str]:
        return [r["url"] for r in self.references if PATCH_TAGS & set(r.get("tags", []))]


_METRIC_KEYS = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}


def parse_nvd_cve(item: dict[str, Any]) -> NormalizedCve:
    cve = item["cve"]
    cve_id = cve["id"].strip().upper()
    if not CVE_ID_RE.match(cve_id):
        raise ValueError(f"invalid CVE id {cve_id!r}")
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)

    metrics: list[dict[str, Any]] = []
    for key, version in _METRIC_KEYS.items():
        for m in cve.get("metrics", {}).get(key, []) or []:
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            sev = (data.get("baseSeverity") or m.get("baseSeverity") or severity_from_score(score)).upper()
            metrics.append({
                "version": version,
                "score": float(score) if score is not None else None,
                "vector": data.get("vectorString"),
                "severity": sev,
                "source": m.get("source"),
                "type": m.get("type"),
            })

    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", []) or []
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })

    refs: dict[str, dict[str, Any]] = {}
    for r in cve.get("references", []) or []:
        url = r.get("url", "").strip()
        if not url.lower().startswith(("http://", "https://")):
            continue  # drop javascript:/data: or malformed links before they ever reach the UI
        entry = refs.setdefault(url, {"url": url, "source": r.get("source"), "tags": []})
        entry["tags"] = sorted(set(entry["tags"]) | set(r.get("tags", [])))

    products: dict[tuple, ProductRef] = {}
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                parts = split_cpe(match.get("criteria", ""))
                if len(parts) < 6 or parts[0] != "cpe":
                    continue
                p = ProductRef(
                    vendor=parts[3][:128],
                    product=parts[4][:256],
                    cpe=match.get("criteria", "")[:512],
                    version_start_including=match.get("versionStartIncluding"),
                    version_start_excluding=match.get("versionStartExcluding"),
                    version_end_including=match.get("versionEndIncluding"),
                    version_end_excluding=match.get("versionEndExcluding"),
                    vulnerable=bool(match.get("vulnerable", True)),
                )
                products.setdefault((p.cpe, p.version_start_including, p.version_end_excluding,
                                     p.version_end_including), p)

    return NormalizedCve(
        cve_id=cve_id,
        description=desc,
        vuln_status=cve.get("vulnStatus"),
        published_at=parse_dt(cve.get("published")),
        last_modified_at=parse_dt(cve.get("lastModified")),
        cvss_metrics=metrics,
        cwes=cwes,
        references=list(refs.values()),
        products=list(products.values()),
        kev_name=cve.get("cisaVulnerabilityName"),
    )


def derive_title(description: str | None, cve_id: str) -> str:
    if not description:
        return cve_id
    first = re.split(r"(?<=[.!?])\s", description.strip(), maxsplit=1)[0]
    return first if len(first) <= 160 else first[:157].rstrip() + "…"

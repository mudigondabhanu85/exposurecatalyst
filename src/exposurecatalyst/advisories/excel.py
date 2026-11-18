"""Branded Excel export of affected assets + CSV/XLSX import of manual asset rows."""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, date, datetime
from typing import Any

from openpyxl import Workbook, load_workbook
from openpyxl.drawing.image import Image as XLImage
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from exposurecatalyst.advisories.render import _cve_view, logo_bytes
from exposurecatalyst.advisories.service import DETECTION_METHODS, exposure, remediation_timeframes, shown_assets
from exposurecatalyst.models import Advisory, Cve

NAVY = "0B1B33"
SURFACE_ALT = "EEF1F5"
# Excel has no font fallback chain: Inter is used where installed (brand), but recipients without it
# would get an arbitrary substitute, so Calibri (Excel default) is the safe brand-compatible choice.
FONT = "Calibri"
HEADER_FONT = Font(name=FONT, bold=True, color="FFFFFF", size=11)
HEADER_FILL = PatternFill("solid", fgColor=NAVY)
BODY_FONT = Font(name=FONT, size=11, color=NAVY)
_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")

ASSET_COLUMNS = [
    ("hostname", "Hostname"), ("ip_address", "IP address"), ("os", "OS"), ("cloud_account", "Cloud account"),
    ("resource_id", "Resource ID"), ("owner", "Owner"), ("business_unit", "Business unit"),
    ("environment", "Environment"), ("support_group", "Support group"), ("asset_class", "Asset class"),
    ("due", "Remediation due"), ("detection_date", "Detection date"), ("source", "Source"),
    ("source_ref", "Plugin / QID / ID"), ("detection_method", "Detection method"), ("entry", "Entry"),
]
UNASSIGNED = "(Unassigned)"


def safe_cell(value: Any) -> Any:
    """CSV/formula injection guard (OWASP): text starting with = + - @ is prefixed and kept as text."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIX):
        return "'" + value
    return value


def _header(ws: Worksheet, row: int, labels: list[str]) -> None:
    for col, label in enumerate(labels, start=1):
        c = ws.cell(row=row, column=col, value=label)
        c.font, c.fill = HEADER_FONT, HEADER_FILL
        c.alignment = Alignment(vertical="center")


def _write_rows(ws: Worksheet, start_row: int, rows: list[list[Any]]) -> None:
    for r, values in enumerate(rows, start=start_row):
        for col, v in enumerate(values, start=1):
            c = ws.cell(row=r, column=col, value=safe_cell(v))
            if isinstance(v, str):
                c.data_type = "s"  # never let openpyxl treat a value as a formula
            c.font = BODY_FONT


def _fit(ws: Worksheet, min_w: int = 8, max_w: int = 60) -> None:
    widths: dict[int, int] = {}
    for row in ws.iter_rows():
        for c in row:
            if c.value is not None:
                widths[c.column] = max(widths.get(c.column, 0), len(str(c.value)))
    for col, w in widths.items():
        ws.column_dimensions[get_column_letter(col)].width = max(min_w, min(max_w, w + 2))


def _asset_sheet(wb: Workbook, title: str, rows: list[list[Any]]) -> None:
    ws = wb.create_sheet(title=title)
    _header(ws, 1, [label for _, label in ASSET_COLUMNS])
    _write_rows(ws, 2, rows)
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    _fit(ws)


def _sheet_name(name: str, used: set[str]) -> str:
    base = re.sub(r"[\[\]:*?/\\]", "-", name)[:28] or "Source"
    candidate, i = base, 2
    while candidate.lower() in used:
        candidate, i = f"{base[:25]}-{i}", i + 1
    used.add(candidate.lower())
    return candidate


def _ownership_sheet(wb: Workbook, unique: list[dict]) -> None:
    """Unique affected assets by division (business unit), by support group, and division × support group."""
    ws = wb.create_sheet(title="Ownership Summary")

    def tally(keyf) -> list[tuple[Any, int]]:
        counts: dict[Any, int] = {}
        for u in unique:
            k = keyf(u)
            counts[k] = counts.get(k, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))

    div = lambda u: u["business_unit"] or UNASSIGNED  # noqa: E731
    grp = lambda u: u["support_group"] or UNASSIGNED  # noqa: E731
    row = 1
    for title, label, data in (("By division", "Division / business unit", tally(div)),
                               ("By support group", "Support group", tally(grp))):
        ws.cell(row=row, column=1, value=title).font = Font(name=FONT, bold=True, size=12, color=NAVY)
        _header(ws, row + 1, [label, "Affected assets"])
        _write_rows(ws, row + 2, [[k, v] for k, v in data] + [["Total", len(unique)]])
        ws.cell(row=row + 2 + len(data), column=1).font = Font(name=FONT, bold=True, color=NAVY)
        row += len(data) + 5
    ws.cell(row=row, column=1, value="By division and support group").font = Font(name=FONT, bold=True, size=12,
                                                                                  color=NAVY)
    _header(ws, row + 1, ["Division / business unit", "Support group", "Affected assets"])
    _write_rows(ws, row + 2, [[d, g, n] for (d, g), n in tally(lambda u: (div(u), grp(u)))])
    unowned = sum(1 for u in unique if not u["support_group"])
    if unowned:
        r = row + 3 + len(tally(lambda u: (div(u), grp(u))))
        ws.cell(row=r, column=1, value=f"{unowned} asset(s) have no support group — the risk owner should help "
                                       "identify ownership.").font = Font(name=FONT, italic=True, color=NAVY)
    _fit(ws)


def build_workbook(adv: Advisory, cve: Cve | None) -> bytes:
    exp = exposure(adv)
    c = _cve_view(cve)
    due_by_class = {t["asset_class"].strip().lower(): t["due"] for t in remediation_timeframes(adv)}

    def due(asset_class: str | None) -> Any:
        return due_by_class.get((asset_class or "").strip().lower(), adv.sla_due_date)

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"

    logo = XLImage(io.BytesIO(logo_bytes()))  # brand asset, scaled proportionally to the 40 px header size
    logo.width, logo.height = 211, 40
    ws.add_image(logo, "A1")
    ws.row_dimensions[1].height = 34
    ws.row_dimensions[2].height = 8

    summary = [
        ("Advisory ID", adv.advisory_id), ("CVE", adv.cve_id), ("Title", adv.title or ""),
        ("Severity", adv.severity), ("CVSS", c["cvss"]), ("EPSS", c["epss"]), ("CISA KEV", c["kev"]),
        ("Exploit status", c["exploit"]), ("Type", adv.vuln_type or ""),
        ("Affected products", adv.affected_products or ""),
        ("Remediation due (SLA)", adv.sla_due_date), ("Owner / contact", adv.owner_contact or ""),
        ("Total unique affected assets", exp.total_unique), ("Status", adv.status),
        ("Generated", datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")),
    ]
    _header(ws, 4, ["Field", "Value"])
    _write_rows(ws, 5, [list(r) for r in summary])
    for r in range(5, 5 + len(summary)):
        ws.cell(row=r, column=2).alignment = Alignment(horizontal="left")
        ws.cell(row=r, column=1).font = Font(name=FONT, bold=True, color=NAVY)
        ws.cell(row=r, column=1).fill = PatternFill("solid", fgColor=SURFACE_ALT)

    m0 = 6 + len(summary)
    _header(ws, m0, ["Source", "Check available", "Validated", "Affected asset count", "Detection method",
                     "Last checked", "Entry", "Note"])
    _write_rows(ws, m0 + 1, [[r.source, r.check_label, r.validated,
                              None if r.validated == "Not Integrated" else r.asset_count, r.method_label,
                              r.last_checked.strftime("%Y-%m-%d %H:%M") if r.last_checked else "",
                              "Manual" if r.manual else "", r.note or r.finding] for r in exp.rows])
    tf = remediation_timeframes(adv)
    if tf:
        t0 = m0 + 3 + len(exp.rows)
        _header(ws, t0, ["Asset classification", "Remediation requirement (days)", "Due by"])
        _write_rows(ws, t0 + 1, [[t["asset_class"], t["days"], t["due"]] for t in tf])
    ws.freeze_panes = "A5"
    _fit(ws)
    ws.column_dimensions["A"].width = max(ws.column_dimensions["A"].width or 0, 30)

    def entry(manual: bool) -> str:
        return "Manual" if manual else "Integration"

    consolidated = [[u["hostname"], u["ip_address"], u["os"], u["cloud_account"], u["resource_id"], u["owner"],
                     u["business_unit"], u["environment"], u["support_group"], u["asset_class"], due(u["asset_class"]),
                     u["detection_date"], ", ".join(u["sources"]), ", ".join(u["source_refs"]),
                     ", ".join(u["detection_methods"]), entry(u["manual"])] for u in exp.unique_assets]
    _asset_sheet(wb, "All Assets (Deduplicated)", consolidated)
    _ownership_sheet(wb, exp.unique_assets)

    used = {"summary", "all assets (deduplicated)", "ownership summary"}
    by_source: dict[str, list] = {}
    for a in shown_assets(adv):
        by_source.setdefault(a.source, []).append(a)
    for src, assets in by_source.items():
        rows = [[a.hostname, a.ip_address, a.os, a.cloud_account, a.resource_id, a.owner, a.business_unit,
                 a.environment, a.support_group, a.asset_class, due(a.asset_class), a.detection_date, a.source,
                 a.source_ref, DETECTION_METHODS.get(a.detection_method or "", a.detection_method),
                 entry(a.is_manual)] for a in assets]
        _asset_sheet(wb, _sheet_name(src, used), rows)

    wb.properties.title = f"{adv.advisory_id} {adv.cve_id} affected assets"
    wb.properties.creator = "ExposureCatalyst"
    out = io.BytesIO()
    wb.save(out)
    return _set_logo_alt_text(out.getvalue())


def _set_logo_alt_text(xlsx: bytes) -> bytes:
    """openpyxl hard-codes image alt text to "Picture"; brand/accessibility require "ExposureCatalyst"."""
    import zipfile

    src, dst = zipfile.ZipFile(io.BytesIO(xlsx)), io.BytesIO()
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename.startswith("xl/drawings/drawing") and item.filename.endswith(".xml"):
                data = data.replace(b'name="Image 1" descr="Picture"',
                                    b'name="ExposureCatalyst logo" descr="ExposureCatalyst"')
            z.writestr(item, data)
    return dst.getvalue()


def workbook_name(adv: Advisory) -> str:
    return f"{adv.advisory_id}_{adv.cve_id}_affected_assets.xlsx"


# ---- import -----------------------------------------------------------------------------------

ALIASES = {
    "hostname": {"hostname", "host", "host name", "fqdn", "dns name", "computer name", "asset name", "name"},
    "ip_address": {"ip", "ip address", "ipv4", "ip_address", "address"},
    "os": {"os", "operating system", "platform"},
    "cloud_account": {"cloud account", "account", "account id", "subscription", "project"},
    "resource_id": {"resource id", "resource_id", "instance id", "arn", "cloud resource id"},
    "owner": {"owner", "asset owner", "contact"},
    "business_unit": {"business unit", "bu", "department"},
    "environment": {"environment", "env"},
    "detection_date": {"detection date", "detected", "first detected", "first seen", "date"},
    "source": {"source", "tool", "scanner"},
    "source_ref": {"plugin", "qid", "plugin id", "finding id", "id", "plugin / qid / id", "source ref"},
    "support_group": {"support group", "support team", "assignment group", "resolver group", "support_group"},
    "asset_class": {"asset class", "asset classification", "classification", "asset_class", "asset type"},
    "detection_method": {"detection method", "method", "detection", "detection_method"},
}
_METHOD_ALIASES = {**{k: k for k in DETECTION_METHODS}, **{v.lower(): k for k, v in DETECTION_METHODS.items()},
                   "scanner": "vulnerability_check", "vulnerability scan": "vulnerability_check",
                   "inventory": "software_inventory", "software": "software_inventory", "cmdb": "asset_inventory"}
_LOOKUP = {alias: field for field, aliases in ALIASES.items() for alias in aliases}
LIMITS = {"hostname": 255, "ip_address": 64, "os": 128, "cloud_account": 128, "resource_id": 512, "owner": 200,
          "business_unit": 200, "environment": 64, "source": 64, "source_ref": 128, "support_group": 200,
          "asset_class": 100}


class ImportError_(ValueError):
    pass


def _rows_from_upload(filename: str, data: bytes) -> list[list[Any]]:
    name = filename.lower()
    if name.endswith(".csv"):
        text = data.decode("utf-8-sig", errors="replace")
        return [row for row in csv.reader(io.StringIO(text))]
    if name.endswith(".xlsx"):
        if not data.startswith(b"PK"):
            raise ImportError_("not a valid .xlsx file")
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)  # data_only: never evaluate formulas
        ws = wb.worksheets[0]
        return [list(r) for r in ws.iter_rows(values_only=True)]
    raise ImportError_("upload a .csv or .xlsx file")


def _to_date(v: Any) -> date | None:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v).strip()[:10])
    except ValueError:
        return None


def parse_assets(filename: str, data: bytes, *, default_source: str, max_rows: int) -> tuple[list[dict], list[str]]:
    rows = _rows_from_upload(filename, data)
    if not rows:
        raise ImportError_("file is empty")
    header = [_LOOKUP.get(str(h or "").strip().lower()) for h in rows[0]]
    if not any(header):
        raise ImportError_("no recognised columns — include a header such as Hostname, IP address, Source")
    out, errors = [], []
    for n, row in enumerate(rows[1:], start=2):
        if len(out) >= max_rows:
            errors.append(f"stopped after {max_rows} rows (EXCAT_UPLOAD_MAX_ROWS)")
            break
        rec: dict[str, Any] = {}
        for field, value in zip(header, row, strict=False):
            if field and value not in (None, ""):
                rec[field] = value
        if not any(rec.get(k) for k in ("hostname", "ip_address", "resource_id")):
            if any(v not in (None, "") for v in row):
                errors.append(f"row {n}: needs a hostname, IP address or resource ID")
            continue
        clean: dict[str, Any] = {}
        for field, limit in LIMITS.items():
            if rec.get(field) is not None:
                clean[field] = str(rec[field]).strip()[:limit]
        clean["detection_date"] = _to_date(rec.get("detection_date"))
        method = _METHOD_ALIASES.get(str(rec.get("detection_method") or "").strip().lower())
        if method:
            clean["detection_method"] = method
        clean["source"] = clean.get("source") or default_source
        out.append(clean)
    return out, errors

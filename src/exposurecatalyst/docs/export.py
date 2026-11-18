"""Documentation exports: one DOCX and one standalone single-file HTML per audience guide.

Pipeline
  1. Pick the guide's pages from the MkDocs nav (same order as the site).
  2. Convert MkDocs/pymdown syntax to Pandoc Markdown: snippets, admonitions → callout divs, <figure> → captioned
     images, Mermaid fences → pre-rendered images, cross-page links → internal anchors, image paths.
  3. Pandoc (local ≥ 3, otherwise the pinned Docker image) with a branded reference.docx generated from Pandoc's
     default: numbered headings, TOC, 300 DPI images.
  4. DOCX post-processing (python-docx): cover page (logo, title, version, date, classification), headers and
     footers with page numbers, landscape sections for wide diagrams, fields refreshed on open.
  5. HTML: --embed-resources, so CSS, fonts, logo and diagrams live inside the one file.

Mermaid diagrams are rendered with mermaid-cli (Docker) into docs/assets/mermaid/<hash>.{svg,png} and
committed, like the architecture diagrams, so builds without Docker (the image build) still work.
"""

from __future__ import annotations

import copy
import hashlib
import html
import json
import os
import re
import shutil
import subprocess  # noqa: S404  # nosec B404
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from exposurecatalyst import __version__
from exposurecatalyst.config import PROJECT_ROOT
from exposurecatalyst.docs.guides import GUIDES, Guide, export_filename

DOCS = PROJECT_ROOT / "docs"
EXPORTS = PROJECT_ROOT / "dist" / "docs" / "exports"
WORK = EXPORTS / ".build"
MERMAID_OUT = DOCS / "assets" / "mermaid"
FONTS = DOCS / "assets" / "fonts"
LOGO_PNG = PROJECT_ROOT / "brand" / "assets" / "png" / "logo-light@2x.png"
LOGO_SVG = PROJECT_ROOT / "brand" / "assets" / "svg" / "logo-light.svg"
PANDOC_IMAGE = "pandoc/core:3.5-ubuntu"
MERMAID_IMAGE = "minlag/mermaid-cli:11.4.2"
CLASSIFICATION = "Internal"
PANDOC_FROM = "markdown+pipe_tables+fenced_divs+lists_without_preceding_blankline-raw_attribute"

NAVY, ORANGE, SLATE, SURFACE_ALT, BORDER = "0B1B33", "E8541A", "4A5568", "EEF1F5", "D5DBE4"

FENCE = re.compile(r"^\s*(```|~~~)")
MERMAID = re.compile(r"^```mermaid[ \t]*\n(.*?)\n```[ \t]*$", re.M | re.S)
SNIPPET = re.compile(r'^([ \t]*)--8<--[ \t]+"([^"]+)"[ \t]*$', re.M)
FIGURE = re.compile(r"<figure[^>]*>(.*?)</figure>", re.S)
ADMONITION = re.compile(r'^(?P<indent>[ \t]*)(?:!!!|\?\?\?\+?)[ \t]+(?P<kind>[\w-]+)(?:[ \t]+"(?P<title>[^"]*)")?[ \t]*$')
LINK = re.compile(r"(?<![!\]])\[(?P<text>[^\]\n]+)\]\((?P<target>[^)\s]+)\)")
IMAGE = re.compile(r"!\[(?P<alt>[^\]\n]*)\]\((?P<src>[^)\s]+)\)(?P<attrs>\{[^}\n]*\})?")


# --------------------------------------------------------------------------------------------- nav / pages
class _NavLoader(yaml.SafeLoader):
    """mkdocs.yml uses !!python/name tags; we only need the nav, so map every unknown tag to None."""


_NavLoader.add_multi_constructor("", lambda _loader, _suffix, _node: None)


def nav_pages() -> list[tuple[str, str]]:
    """(top-level section title, docs-relative path) in site order."""
    nav = yaml.load((PROJECT_ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=_NavLoader)["nav"]  # noqa: S506  # nosec B506
    out: list[tuple[str, str]] = []

    def walk(items, section: str) -> None:
        for item in items:
            if isinstance(item, str):
                out.append((section, item))
            elif isinstance(item, dict):
                for title, value in item.items():
                    if isinstance(value, str):
                        out.append((section or title, value))
                    else:
                        walk(value, section or title)

    walk(nav, "")
    return out


def guide_pages(guide: Guide, nav: list[tuple[str, str]] | None = None) -> list[str]:
    nav = nav if nav is not None else nav_pages()
    pages = [p for s, p in nav if guide.sections is None or s in guide.sections or p in guide.pages]
    return list(dict.fromkeys(pages))


def page_id(rel: str) -> str:
    return "page-" + re.sub(r"[^a-z0-9]+", "-", rel.removesuffix(".md").lower()).strip("-")


# --------------------------------------------------------------------------------------------- mermaid
def mermaid_hash(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()[:16]


def mermaid_sources() -> dict[str, str]:
    found = {}
    for md in sorted(DOCS.rglob("*.md")):
        for m in MERMAID.finditer(md.read_text(encoding="utf-8")):
            found[mermaid_hash(m.group(1))] = m.group(1).strip() + "\n"
    return found


MERMAID_CONFIG = {
    "theme": "base",
    "themeVariables": {"primaryColor": "#" + SURFACE_ALT, "primaryBorderColor": "#" + NAVY, "primaryTextColor": "#" + NAVY,
                       "lineColor": "#" + SLATE, "secondaryColor": "#F7F8FA", "tertiaryColor": "#FFFFFF",
                       "fontFamily": "Inter, Helvetica, Arial, sans-serif", "noteBkgColor": "#F7F8FA",
                       "noteBorderColor": "#" + BORDER, "actorBkg": "#" + SURFACE_ALT, "actorBorder": "#" + NAVY},
}


def render_mermaid(use_docker: bool = False) -> int:
    """Render every Mermaid block to SVG + 3× PNG (≈ 300 DPI at print size). Returns the number rendered."""
    sources = mermaid_sources()
    MERMAID_OUT.mkdir(parents=True, exist_ok=True)
    for stale in MERMAID_OUT.glob("*.*"):
        if stale.stem not in sources:
            stale.unlink()
    todo = {h: c for h, c in sources.items()
            if not ((MERMAID_OUT / f"{h}.svg").exists() and (MERMAID_OUT / f"{h}.png").exists())}
    if not todo:
        return 0
    tmp = WORK / "mermaid"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    (tmp / "config.json").write_text(json.dumps(MERMAID_CONFIG), encoding="utf-8")
    local = shutil.which("mmdc") and not use_docker
    if not local and shutil.which("docker") is None:
        raise SystemExit("Mermaid renders missing and neither mmdc nor Docker is available: "
                         + ", ".join(sorted(todo)))
    for h, code in todo.items():
        (tmp / f"{h}.mmd").write_text(code, encoding="utf-8")
        for ext, extra in (("svg", []), ("png", ["-s", "3"])):
            if local:
                cmd = ["mmdc", "-i", str(tmp / f"{h}.mmd"), "-o", str(tmp / f"{h}.{ext}"), "-c", str(tmp / "config.json")]
            else:
                cmd = ["docker", "run", "--rm", "-u", f"{os.getuid()}:{os.getgid()}", "-v", f"{tmp}:/data",
                       MERMAID_IMAGE, "-i", f"/data/{h}.mmd", "-o", f"/data/{h}.{ext}", "-c", "/data/config.json"]
            _run([*cmd, "-b", "white", *extra])
            shutil.copyfile(tmp / f"{h}.{ext}", MERMAID_OUT / f"{h}.{ext}")
    return len(todo)


# --------------------------------------------------------------------------------------------- markdown conversion
@dataclass
class Context:
    fmt: str                    # "docx" | "html"
    pages: dict[str, str]       # docs-relative path → page anchor id (pages in this guide)


def _expand_snippets(text: str) -> str:
    def sub(m: re.Match) -> str:
        src = (PROJECT_ROOT / m.group(2)).resolve()
        if not src.is_relative_to(PROJECT_ROOT) or not src.is_file():
            raise SystemExit(f"Snippet not found: {m.group(2)}")
        return "\n".join(m.group(1) + line if line else "" for line in src.read_text(encoding="utf-8").splitlines())
    return SNIPPET.sub(sub, text)


def _mermaid_images(text: str, ctx: Context) -> str:
    def sub(m: re.Match) -> str:
        h = mermaid_hash(m.group(1))
        ext = "png" if ctx.fmt == "docx" else "svg"
        path = MERMAID_OUT / f"{h}.{ext}"
        if not path.exists():
            raise SystemExit(f"Mermaid render {path.name} missing — run `python -m exposurecatalyst.docs mermaid --docker`")
        return f"![]({path.relative_to(PROJECT_ROOT).as_posix()})"
    return MERMAID.sub(sub, text)


def _figures(text: str) -> str:
    def sub(m: re.Match) -> str:
        body = m.group(1)
        img = re.search(r"!\[([^\]]*)\]\(([^)\s]+)\)", body)
        if not img:
            return ""
        cap = re.search(r"<figcaption>(.*?)</figcaption>", body, re.S)
        caption = img.group(1)
        if cap:
            caption = re.sub(r"<[^>]+>", "", cap.group(1).split("Downloads:")[0])
            caption = html.unescape(" ".join(caption.split()))
        caption = caption.replace("[", "(").replace("]", ")")
        return f"\n![{caption}]({img.group(2)})\n"
    return FIGURE.sub(sub, text)


def _admonitions(lines: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    in_fence = False
    while i < len(lines):
        line = lines[i]
        if FENCE.match(line):
            in_fence = not in_fence
        m = None if in_fence else ADMONITION.match(line)
        if not m:
            out.append(line)
            i += 1
            continue
        indent, kind = m.group("indent"), m.group("kind").lower()
        title = m.group("title") or kind.capitalize()
        inner_prefix = indent + "    "
        body: list[str] = []
        i += 1
        while i < len(lines) and (not lines[i].strip() or lines[i].startswith(inner_prefix)):
            body.append(lines[i][len(inner_prefix):] if lines[i].strip() else "")
            i += 1
        while body and not body[-1]:
            body.pop()
        body = _admonitions(body)
        # Headings inside a callout would become numbered chapters — render them as bold lines instead.
        fenced = False
        for j, b in enumerate(body):
            if FENCE.match(b):
                fenced = not fenced
            elif not fenced and (h := re.match(r"^#{1,6}\s+(.*)$", b)):
                body[j] = f"**{h.group(1)}**"
        out += [f'{indent}::: {{.admonition .{kind} custom-style="Callout"}}', f"{indent}**{title}**", ""]
        out += [indent + b if b else "" for b in body]
        out += [f"{indent}:::", ""]
    return out


def _resolve(target: str, src_rel: str) -> Path | None:
    base = (DOCS / src_rel).parent
    for cand in ((base / target), (PROJECT_ROOT / target)):
        p = cand.resolve()
        if p.is_relative_to(PROJECT_ROOT) and p.exists():
            return p
    return None


def _links(text: str, src_rel: str, ctx: Context) -> str:
    def sub(m: re.Match) -> str:
        text_, target = m.group("text"), m.group("target")
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):  # http:, https:, mailto:
            return m.group(0)
        path, _, _frag = target.partition("#")
        if not path:  # in-page anchor: anchors repeat across pages, so point at the page itself
            return f"[{text_}](#{ctx.pages[src_rel]})"
        resolved = _resolve(path, src_rel)
        if resolved and resolved.suffix == ".md" and resolved.is_relative_to(DOCS):
            rel = resolved.relative_to(DOCS).as_posix()
            if rel in ctx.pages:
                return f"[{text_}](#{ctx.pages[rel]})"
        return text_  # page outside this guide, or a download link — keep the words, drop the dead link
    return LINK.sub(sub, text)


def _images(text: str, src_rel: str, ctx: Context) -> str:
    def sub(m: re.Match) -> str:
        src = m.group("src")
        if re.match(r"^[a-z]+:", src, re.I):
            return m.group(0)
        p = _resolve(src, src_rel)
        if p is None:
            raise SystemExit(f"{src_rel}: image not found: {src}")
        if ctx.fmt == "docx" and p.suffix == ".svg" and p.with_suffix(".png").exists():
            p = p.with_suffix(".png")  # Word: the 300-DPI PNG render
        attrs = m.group("attrs") or ""
        return f"![{m.group('alt')}]({p.relative_to(PROJECT_ROOT).as_posix()}){attrs}"
    return IMAGE.sub(sub, text)


def _headings(lines: list[str], anchor: str) -> list[str]:
    out, in_fence, seen_h1 = [], False, False
    for line in lines:
        if FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and (m := re.match(r"^(#{1,6})\s+(.*?)\s*$", line)):
            level, title = len(m.group(1)), m.group(2)
            if level == 1 and not seen_h1:
                seen_h1 = True
                line = f"# {title} {{#{anchor}}}"
            elif level == 1:
                line = f"## {title}"
        out.append(line)
    if not seen_h1:
        out.insert(0, f"# {anchor} {{#{anchor}}}")
    return out


def convert_page(rel: str, ctx: Context) -> str:
    text = (DOCS / rel).read_text(encoding="utf-8")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = _expand_snippets(text)
    text = _mermaid_images(text, ctx)
    text = _figures(text)
    text = re.sub(r"^[ \t]*</?div\b[^>]*>[ \t]*$", "", text, flags=re.M)
    lines = _admonitions(text.splitlines())
    lines = _headings(lines, ctx.pages[rel])
    text = "\n".join(lines)
    text = _links(text, rel, ctx)
    text = _images(text, rel, ctx)
    return text.strip() + "\n"


def combined_markdown(guide: Guide, fmt: str, nav: list[tuple[str, str]] | None = None) -> str:
    if not (DOCS / "assets" / "brand").is_dir():  # generated (git-ignored): needed in a clean checkout / CI
        from exposurecatalyst.docs.build import sync_brand

        sync_brand()
    pages = guide_pages(guide, nav)
    ctx = Context(fmt, {p: page_id(p) for p in pages})
    return "\n\n".join(convert_page(p, ctx) for p in pages)


# --------------------------------------------------------------------------------------------- pandoc
def _pandoc_cmd() -> list[str]:
    local = shutil.which("pandoc")
    if local:
        out = subprocess.run([local, "--version"], capture_output=True, text=True, check=False).stdout  # noqa: S603  # nosec B603
        if (m := re.match(r"pandoc (\d+)", out)) and int(m.group(1)) >= 3:
            return [local]
    if shutil.which("docker") is None:
        raise SystemExit("Pandoc ≥ 3 not found and Docker unavailable — cannot export DOCX/HTML.")
    return ["docker", "run", "--rm", "-u", f"{os.getuid()}:{os.getgid()}", "-v", f"{PROJECT_ROOT}:/work", "-w", "/work",
            PANDOC_IMAGE]


def _rel(p: Path) -> str:
    return p.relative_to(PROJECT_ROOT).as_posix()


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, cwd=PROJECT_ROOT, **kw)  # noqa: S603  # nosec B603


# --------------------------------------------------------------------------------------------- reference.docx
def build_reference_docx(pandoc: list[str]) -> Path:
    from docx.enum.style import WD_STYLE_TYPE
    from docx.shared import Pt, RGBColor

    raw = WORK / "reference-default.docx"
    _run([*pandoc, "-o", _rel(raw), "--print-default-data-file", "reference.docx"])
    from docx import Document

    doc = Document(str(raw))
    styles = doc.styles

    def font(name: str, family: str | None = None, size: float | None = None, color: str | None = None,
             bold: bool | None = None, italic: bool | None = None) -> None:
        try:
            st = styles[name]
        except KeyError:
            return
        f = st.font
        if family:
            f.name = family
            rpr = st.element.get_or_add_rPr()
            rfonts = rpr.find(_qn("w:rFonts"))
            for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
                rfonts.set(_qn(attr), family)
            for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
                rfonts.attrib.pop(_qn(attr), None)
        if size:
            f.size = Pt(size)
        if color:
            f.color.rgb = RGBColor.from_string(color)
        if bold is not None:
            f.bold = bold
        if italic is not None:
            f.italic = italic

    font("Normal", "Inter", 10, NAVY)
    for name in ("Body Text", "First Paragraph", "Compact"):
        font(name, "Inter", 10, NAVY)
    font("Title", "Space Grotesk", 30, NAVY, bold=True)
    font("Subtitle", "Inter", 14, SLATE, bold=False, italic=False)
    font("Author", "Inter", 11, SLATE)
    font("Date", "Inter", 11, SLATE)
    for level, size in ((1, 20), (2, 15), (3, 12.5), (4, 11), (5, 10.5), (6, 10)):
        font(f"Heading {level}", "Space Grotesk", size, NAVY, bold=True, italic=False)
    font("TOC Heading", "Space Grotesk", 18, NAVY, bold=True)
    font("Image Caption", "Inter", 9, SLATE, italic=True)
    font("Table Caption", "Inter", 9, SLATE, italic=True)
    font("Hyperlink", color=NAVY)
    font("Verbatim Char", "Consolas", 9)
    font("Source Code", "Consolas", 9)

    h1 = styles["Heading 1"].element.get_or_add_pPr()
    h1.append(_el("w:pageBreakBefore"))
    h1.append(_el("w:pBdr", _el("w:bottom", val="single", sz="12", space="4", color=ORANGE)))  # brand accent rule
    code = styles.add_style("Source Code", WD_STYLE_TYPE.PARAGRAPH)  # pandoc applies it to code blocks
    code.base_style = styles["Normal"]
    font("Source Code", "Consolas", 8.5, NAVY)
    code.paragraph_format.space_before = Pt(0)
    code.paragraph_format.space_after = Pt(0)
    _shade(code.element.get_or_add_pPr(), "F7F8FA")

    callout = styles.add_style("Callout", WD_STYLE_TYPE.PARAGRAPH)
    callout.base_style = styles["Body Text"]
    ppr = callout.element.get_or_add_pPr()
    ppr.append(_el("w:pBdr", _el("w:left", val="single", sz="24", space="8", color=ORANGE)))
    _shade(ppr, SURFACE_ALT)
    ppr.append(_el("w:ind", left="240", right="120"))

    table = styles["Table"].element
    tblpr = table.find(_qn("w:tblPr"))
    if tblpr is None:
        tblpr = _el("w:tblPr")
        table.append(tblpr)
    edges = [_el(f"w:{e}", val="single", sz="4", space="0", color=BORDER) for e in
             ("top", "left", "bottom", "right", "insideH", "insideV")]
    for old in tblpr.findall(_qn("w:tblBorders")):
        tblpr.remove(old)
    tblpr.append(_el("w:tblBorders", *edges))
    tblpr.append(_el("w:tblCellMar", _el("w:left", w="80", type="dxa"), _el("w:right", w="80", type="dxa")))
    for old in table.findall(_qn("w:tblStylePr")):
        if old.get(_qn("w:type")) == "firstRow":
            table.remove(old)
    table.append(_el("w:tblStylePr",
                     _el("w:rPr", _el("w:b"), _el("w:color", val="FFFFFF")),
                     _el("w:tcPr", _el("w:shd", val="clear", color="auto", fill=NAVY)), type="firstRow"))

    out = WORK / "reference.docx"
    doc.save(str(out))
    return out


def _qn(tag: str) -> str:
    from docx.oxml.ns import qn
    return qn(tag)


def _el(tag: str, *children, **attrs):
    from docx.oxml import OxmlElement
    e = OxmlElement(tag)
    for k, v in attrs.items():
        e.set(_qn(f"w:{k}"), str(v))
    for c in children:
        e.append(c)
    return e


def _shade(ppr, fill: str) -> None:
    ppr.append(_el("w:shd", val="clear", color="auto", fill=fill))


# --------------------------------------------------------------------------------------------- DOCX post-processing
def _field(paragraph, instr: str) -> None:
    for kind, text in (("begin", None), ("instr", instr), ("separate", None), ("text", "1"), ("end", None)):
        run = paragraph.add_run()
        if kind == "instr":
            it = _el("w:instrText")
            it.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            it.text = f" {text} "
            run._r.append(it)
        elif kind == "text":
            run.text = text
        else:
            run._r.append(_el("w:fldChar", fldCharType=kind))


def _section_landscape(sect_pr, landscape: bool):
    s = copy.deepcopy(sect_pr)
    for ref in s.findall(_qn("w:headerReference")) + s.findall(_qn("w:footerReference")):
        s.remove(ref)
    for tp in s.findall(_qn("w:titlePg")):
        s.remove(tp)
    pg = s.find(_qn("w:pgSz"))
    w, h = int(pg.get(_qn("w:w"))), int(pg.get(_qn("w:h")))
    if landscape:
        pg.set(_qn("w:w"), str(max(w, h)))
        pg.set(_qn("w:h"), str(min(w, h)))
        pg.set(_qn("w:orient"), "landscape")
    return s


WIDE_RATIO = 1.45  # width / height above which a diagram gets its own landscape page
MIN_WIDE_EMU = 4 * 914400  # …and only if it is a full-width figure (≥ 4 in), never an inline image


def _fit_tall_figures(doc) -> int:
    """Word does not shrink a picture taller than the text area: it runs off the page and is cut. Scale tall
    portrait figures (proportionally) to the page's usable height. Wide figures are handled by the landscape step."""
    final = doc.element.body.find(_qn("w:sectPr"))
    pg, mar = final.find(_qn("w:pgSz")), final.find(_qn("w:pgMar"))
    twip = 635  # EMU per twip
    max_h = (int(pg.get(_qn("w:h"))) - int(mar.get(_qn("w:top"))) - int(mar.get(_qn("w:bottom"))) - 1100) * twip
    count = 0
    for extent in doc.element.body.iter(_qn("wp:extent")):
        cx, cy = int(extent.get("cx")), int(extent.get("cy"))
        if cy <= max_h or cy == 0:
            continue
        scale = max_h / cy
        new = (str(int(cx * scale)), str(int(cy * scale)))
        extent.set("cx", new[0])
        extent.set("cy", new[1])
        inline = extent.getparent()
        for ext in inline.iter(_qn("a:ext")):  # the picture's own size must match the frame
            if ext.get("cx") and ext.get("cy"):
                ext.set("cx", new[0])
                ext.set("cy", new[1])
        count += 1
    return count


def _landscape_wide_figures(doc) -> int:
    body = doc.element.body
    final = body.find(_qn("w:sectPr"))
    pg, mar = final.find(_qn("w:pgSz")), final.find(_qn("w:pgMar"))
    page_w, page_h = int(pg.get(_qn("w:w"))), int(pg.get(_qn("w:h")))
    m = {k: int(mar.get(_qn(f"w:{k}"))) for k in ("top", "bottom", "left", "right")}
    twip = 635  # EMU per twip
    land_w = (max(page_w, page_h) - m["left"] - m["right"]) * twip
    land_h = (min(page_w, page_h) - m["top"] - m["bottom"] - 1100) * twip  # room for the caption
    portrait = _section_landscape(final, landscape=False)
    landscape = _section_landscape(final, landscape=True)
    count = 0
    for p in list(body.iterchildren(_qn("w:p"))):
        extent = p.find(".//" + _qn("wp:extent"))
        if extent is None or p.find(".//" + _qn("pic:pic")) is None:
            continue
        cx, cy = int(extent.get("cx")), int(extent.get("cy"))
        if cy == 0 or cx / cy < WIDE_RATIO or cx < MIN_WIDE_EMU:
            continue
        last = p
        nxt = p.getnext()
        if nxt is not None and nxt.tag == _qn("w:p"):
            style = nxt.find(_qn("w:pPr") + "/" + _qn("w:pStyle"))
            if style is not None and "Caption" in style.get(_qn("w:val"), ""):
                last = nxt
        prev = p.getprevious()
        prev_sect = prev.find(_qn("w:pPr") + "/" + _qn("w:sectPr")) if prev is not None and prev.tag == _qn("w:p") else None
        if prev_sect is not None and prev_sect.find(_qn("w:pgSz")).get(_qn("w:orient")) == "landscape":
            prev_sect.getparent().remove(prev_sect)  # consecutive wide figures share one landscape section
        else:
            holder = _el("w:p")
            p.addprevious(holder)
            holder.append(_el("w:pPr", copy.deepcopy(portrait)))
        ppr = last.find(_qn("w:pPr"))
        if ppr is None:
            ppr = _el("w:pPr")
            last.insert(0, ppr)
        ppr.append(copy.deepcopy(landscape))
        scale = min(land_w / cx, land_h / cy)
        new_cx, new_cy = str(int(cx * scale)), str(int(cy * scale))
        extent.set("cx", new_cx)
        extent.set("cy", new_cy)
        for ext in p.iter(_qn("a:ext")):
            ext.set("cx", new_cx)
            ext.set("cy", new_cy)
        count += 1
    return count


def postprocess_docx(path: Path, guide: Guide, version: str, date: str) -> None:
    from docx import Document
    from docx.enum.text import WD_BREAK, WD_TAB_ALIGNMENT
    from docx.shared import Inches, Pt

    doc = Document(str(path))
    body = doc.element.body
    sect = body.find(_qn("w:sectPr"))  # pandoc's default is an empty <w:sectPr/>: use US Letter, 1" margins
    if sect is None:
        sect = _el("w:sectPr")
        body.append(sect)
    if sect.find(_qn("w:pgSz")) is None:
        sect.append(_el("w:pgSz", w="12240", h="15840"))
    if sect.find(_qn("w:pgMar")) is None:
        sect.append(_el("w:pgMar", top="1440", right="1440", bottom="1440", left="1440", header="720",
                        footer="720", gutter="0"))

    _fit_tall_figures(doc)  # tall diagrams fit the page height instead of running off the page
    wide = _landscape_wide_figures(doc)  # before the cover, so the logo is never treated as a figure

    # Cover: logo above pandoc's title block, version/classification below it, page break before the TOC.
    first = body[0]
    logo = doc.add_paragraph()
    logo.add_run().add_picture(str(LOGO_PNG), width=Inches(2.8))
    logo.paragraph_format.space_before = Pt(96)
    logo.paragraph_format.space_after = Pt(48)
    logo.alignment = 1  # centred, like the title block
    first.addprevious(logo._p)
    toc = next((e for e in body.iterchildren(_qn("w:sdt"))), None)
    meta = doc.add_paragraph(f"Version {version}  ·  {date}", style="Date")
    cls = doc.add_paragraph(f"Classification: {CLASSIFICATION}", style="Date")
    brk = doc.add_paragraph()
    brk.add_run().add_break(WD_BREAK.PAGE)
    anchor = toc if toc is not None else logo._p.getnext()
    for el in (meta._p, cls._p, brk._p):
        anchor.addprevious(el)
    for p in body.iterchildren(_qn("w:p")):  # pandoc's own date paragraph is superseded by ours
        st = p.find(_qn("w:pPr") + "/" + _qn("w:pStyle"))
        if st is not None and st.get(_qn("w:val")) == "Date" and p not in (meta._p, cls._p):
            body.remove(p)
            break

    for i, section in enumerate(doc.sections):
        if i == 0:
            section.different_first_page_header_footer = True  # clean cover page
            header, footer = section.header, section.footer
            header.is_linked_to_previous = False
            footer.is_linked_to_previous = False
            text_w = section.page_width - section.left_margin - section.right_margin
            hp = header.paragraphs[0]
            hp.text = f"ExposureCatalyst — {guide.title}\t{CLASSIFICATION}"
            hp.paragraph_format.tab_stops.add_tab_stop(text_w, WD_TAB_ALIGNMENT.RIGHT)
            fp = footer.paragraphs[0]
            fp.text = f"Version {version} · {date}\tPage "
            fp.paragraph_format.tab_stops.add_tab_stop(text_w, WD_TAB_ALIGNMENT.RIGHT)
            _field(fp, "PAGE")
            fp.add_run(" of ")
            _field(fp, "NUMPAGES")
            for para in (hp, fp):
                for run in para.runs:
                    run.font.size = Pt(8)
                    run.font.name = "Inter"
        else:
            section.header.is_linked_to_previous = True
            section.footer.is_linked_to_previous = True
            section.different_first_page_header_footer = False

    settings = doc.settings.element
    if settings.find(_qn("w:updateFields")) is None:
        settings.append(_el("w:updateFields", val="true"))  # Word refreshes TOC and page counts on open

    cp = doc.core_properties
    cp.title = f"ExposureCatalyst {guide.title}"
    cp.subject = guide.description
    cp.author = "ExposureCatalyst"
    cp.keywords = f"version {version}; classification {CLASSIFICATION}"
    cp.category = CLASSIFICATION
    cp.version = version
    doc.save(str(path))
    print(f"  {path.name}: {len(doc.sections)} sections, {wide} landscape figure(s)")


# --------------------------------------------------------------------------------------------- HTML
def _export_css() -> str:
    def face(family: str, weight: int, file: str) -> str:
        rel = os.path.relpath(FONTS / file, WORK)
        return (f'@font-face {{ font-family: "{family}"; font-weight: {weight}; font-display: swap; '
                f'src: url("{rel}") format("woff2"); }}\n')

    faces = "".join([face("Inter", 400, "inter-latin-400-normal.woff2"), face("Inter", 500, "inter-latin-500-normal.woff2"),
                     face("Inter", 600, "inter-latin-600-normal.woff2"),
                     face("Space Grotesk", 500, "space-grotesk-latin-500-normal.woff2"),
                     face("Space Grotesk", 700, "space-grotesk-latin-700-normal.woff2")])
    return faces + f"""
:root {{ color-scheme: light; --navy:#{NAVY}; --orange:#{ORANGE}; --slate:#{SLATE}; --alt:#{SURFACE_ALT}; --border:#{BORDER}; }}
html {{ background:#fff; }}
body {{ font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--navy); line-height: 1.6;
       max-width: 62rem; margin: 0 auto; padding: 0 16px 4rem; font-size: 15px; background:#fff; }}
h1, h2, h3, h4, h5 {{ font-family: "Space Grotesk", Inter, sans-serif; font-weight: 700; line-height: 1.25; }}
h1 {{ font-size: 1.9rem; border-bottom: 3px solid var(--orange); padding-bottom: .3rem; margin-top: 3.5rem; }}
h2 {{ font-size: 1.4rem; margin-top: 2.2rem; }} h3 {{ font-size: 1.15rem; }}
.header-section-number {{ color: var(--slate); margin-right: .4em; }}
a {{ color: var(--navy); text-decoration-color: var(--orange); text-underline-offset: 2px; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88em; background: #F7F8FA;
       padding: .05em .3em; border-radius: 4px; }}
pre {{ background: #F7F8FA; border: 1px solid var(--border); border-radius: 6px; padding: .8rem 1rem; overflow-x: auto; }}
pre code {{ background: none; padding: 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .9em; display: block; overflow-x: auto; }}
th {{ background: var(--navy); color: #fff; text-align: left; }}
th, td {{ border: 1px solid var(--border); padding: .4rem .6rem; vertical-align: top; }}
tr:nth-child(even) td {{ background: #F7F8FA; }}
figure {{ margin: 1.5rem 0; text-align: center; }} img {{ max-width: 100%; height: auto; }}
/* Diagrams fit the window (width and height) so the whole diagram is visible; click for full size. */
figure img {{ width: auto; max-height: 85vh; object-fit: contain; cursor: zoom-in; }}
figure img.ec-full {{ max-height: none; cursor: zoom-out; }}
figure figcaption {{ text-align: left; }}
figcaption {{ color: var(--slate); font-size: .85em; font-style: italic; }}
.admonition {{ border-left: 4px solid var(--orange); background: var(--alt); padding: .6rem 1rem; margin: 1rem 0; border-radius: 0 6px 6px 0; }}
.admonition > p:first-child {{ margin-top: 0; }}
.ec-cover {{ padding: 4rem 0 2rem; border-bottom: 1px solid var(--border); }}
.ec-cover img {{ width: 280px; height: auto; }}
.ec-cover .t {{ font-family: "Space Grotesk", Inter, sans-serif; font-size: 2.4rem; font-weight: 700; margin: 2rem 0 .3rem; }}
.ec-cover .s {{ color: var(--slate); font-size: 1.15rem; margin: 0; }}
.ec-cover .m {{ color: var(--slate); font-size: .9rem; }}
nav#TOC {{ border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
nav#TOC ul {{ list-style: none; padding-left: 1.2rem; }} nav#TOC > ul {{ padding-left: 0; }}
nav#TOC a {{ text-decoration: none; }}
.toc-title {{ font-family: "Space Grotesk", Inter, sans-serif; font-weight: 700; font-size: 1.3rem; }}
@media print {{ h1 {{ break-before: page; }} body {{ max-width: none; }} table {{ display: table; }}
  figure {{ break-inside: avoid; }} figure img, figure img.ec-full {{ max-height: 23cm; }} }}
"""


def _cover_html(guide: Guide, version: str, date: str) -> str:
    return (f'<header class="ec-cover"><img src="{_rel(LOGO_SVG)}" alt="ExposureCatalyst">'
            f'<p class="t">{html.escape(guide.title)}</p><p class="s">{html.escape(guide.description)}</p>'
            f'<p class="m">Version {html.escape(version)} · {date} · Classification: {CLASSIFICATION}</p></header>\n')


# --------------------------------------------------------------------------------------------- entry point
def export_all(guides: tuple[Guide, ...] = GUIDES, version: str = __version__) -> Path:
    date = os.environ.get("EXCAT_DOCS_DATE") or datetime.now(UTC).strftime("%Y-%m-%d")
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    pandoc = _pandoc_cmd()
    reference = build_reference_docx(pandoc)
    css = WORK / "export.css"
    css.write_text(_export_css(), encoding="utf-8")
    nav = nav_pages()
    manifest = {"version": version, "date": date, "classification": CLASSIFICATION, "guides": []}
    common = ["-f", PANDOC_FROM, "--toc", "--number-sections", "--resource-path=.", "-M", "toc-title=Contents"]
    for guide in guides:
        files = {}
        for fmt in ("docx", "html"):
            src = WORK / f"{guide.id}.{fmt}.md"
            src.write_text(combined_markdown(guide, fmt, nav), encoding="utf-8")
            out = EXPORTS / export_filename(guide.id, fmt)
            if fmt == "docx":
                _run([*pandoc, _rel(src), *common, "--toc-depth=2", "--dpi=300", "-t", "docx",
                      f"--reference-doc={_rel(reference)}", "-M", f"title=ExposureCatalyst {guide.title}",
                      "-M", f"subtitle={guide.description}", "-M", f"date={date}", "-o", _rel(out)])
                postprocess_docx(out, guide, version, date)
            else:
                cover = WORK / f"{guide.id}.cover.html"
                cover.write_text(_cover_html(guide, version, date), encoding="utf-8")
                zoom = WORK / "zoom.html"  # click a diagram to toggle full size (no external resources)
                zoom.write_text("<script>document.querySelectorAll('figure img').forEach(function (i) {"
                                "i.addEventListener('click', function () { i.classList.toggle('ec-full'); }); });"
                                "</script>\n", encoding="utf-8")
                _run([*pandoc, _rel(src), *common, "--toc-depth=3", "-t", "html5", "-s", "--embed-resources",
                      f"--css={_rel(css)}", f"--include-before-body={_rel(cover)}",
                      f"--include-after-body={_rel(zoom)}",
                      "-M", f"pagetitle=ExposureCatalyst {guide.title} {version}", "-M", "lang=en", "-o", _rel(out)])
            files[fmt] = {"name": out.name, "size": out.stat().st_size}
        manifest["guides"].append({"id": guide.id, "title": guide.title, "files": files})
    (EXPORTS / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    shutil.rmtree(WORK, ignore_errors=True)
    return EXPORTS

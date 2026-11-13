"""Shared AWS-architecture styling for every ExposureCatalyst diagram.

* ``label(role, service)``   — bold role over the AWS service name (AWS reference-architecture convention)
* ``GROUP``                  — boundary styles: AWS Cloud → Region → VPC → AZ → subnets, layers, externals
* ``EDGE``                   — edge styles: sync, async/event, egress (through Network Firewall), trust boundary
* ``embed_svg_images``       — inline icon PNGs into the SVG so it renders anywhere (docs site, offline HTML)
* ``Drawio``                 — writes an editable .drawio using draw.io's AWS4 shape library (mxgraph.aws4.*)
"""

from __future__ import annotations

import base64
import html
import os
import re
from pathlib import Path
from xml.sax.saxutils import escape

FONT = "Helvetica"          # AWS-style node/edge labels (unchanged)
AWS_INK = "#232F3E"

# ---- Brand (title block + legend only; AWS icons and colors stay as AWS defines them) -------------
BRAND_NAVY, BRAND_ORANGE, BRAND_SLATE, BRAND_BORDER = "#0B1B33", "#E8541A", "#4A5568", "#D5DBE4"
BRAND_HEADING_FONT, BRAND_BODY_FONT = "Space Grotesk", "Inter"
BRAND_DIR = Path(os.environ.get("EXCAT_BRAND_DIR", Path(__file__).resolve().parents[2] / "brand"))
BRAND_MARK_PNG = BRAND_DIR / "assets" / "png" / "mark-light-512.png"  # shown at 64 px (brand minimum)


def title_block(title: str, subtitle: str) -> str:
    """Brand title block: mark (64 px) + title in Space Grotesk navy + subtitle, orange rule."""
    return (f'<<table border="0" cellborder="0" cellspacing="0" cellpadding="6"><tr>'
            f'<td fixedsize="true" width="64" height="64"><img src="{BRAND_MARK_PNG}" scale="true"/></td>'
            f'<td align="left" balign="left"><font face="{BRAND_HEADING_FONT}" point-size="26" color="{BRAND_NAVY}">'
            f'<b>{html.escape(title)}</b></font><br/><font face="{BRAND_BODY_FONT}" point-size="13" '
            f'color="{BRAND_SLATE}">{html.escape(subtitle)}</font></td></tr>'
            f'<tr><td colspan="2" height="4" bgcolor="{BRAND_ORANGE}"></td></tr></table>>')

# ---- Graphviz ("diagrams") styles -----------------------------------------------------------------


def label(role: str, service: str = "") -> str:
    if not service:
        return f"<<b>{html.escape(role)}</b>>"
    return f'<<b>{html.escape(role)}</b><br/><font point-size="10" color="#545B64">{html.escape(service)}</font>>'


_CIRCLED = {chr(0x2460 + i): str(i + 1) for i in range(20)}  # ① → 1


def edge_label(text: str) -> str:
    """AWS-style numbered badge: a leading ①..⑳ becomes a filled dark circle-ish badge."""
    num = _CIRCLED.get(text[:1])
    body = html.escape(text[1:].strip() if num else text)
    if not num:
        return f'<<font point-size="10">{body}</font>>'
    return (f'<<table border="0" cellborder="0" cellspacing="0" cellpadding="1"><tr>'
            f'<td bgcolor="#232F3E" style="rounded"><font color="white" point-size="10"><b>&nbsp;{num}&nbsp;</b></font></td>'
            f'<td><font point-size="10">&nbsp;{body}</font></td></tr></table>>')


def node_attrs(lines: int = 2) -> dict:
    return {"height": str(1.9 + 0.35 * lines), "fontsize": "12", "fontname": FONT}


def cluster_label(title: str, subtitle: str = "") -> str:
    sub = f'<br/><font point-size="10" color="#545B64">{html.escape(subtitle)}</font>' if subtitle else ""
    return f"<<b>{html.escape(title)}</b>{sub}>"


def _g(color: str, fill: str = "#FFFFFF", style: str = "solid", pen: str = "2") -> dict:
    return {"pencolor": color, "bgcolor": fill, "style": style, "penwidth": pen, "fontname": FONT,
            "fontsize": "13", "fontcolor": color if color != "#AEB6BE" else AWS_INK, "labeljust": "l",
            "margin": "18"}


GROUP = {
    "aws_cloud": _g(AWS_INK),
    "region": _g("#147EBA", style="dashed"),  # dashed blue, per AWS group conventions
    "vpc": _g("#8C4FFF"),
    "az": _g("#147EBA", style="dashed", pen="1.5"),
    "public": _g("#7AA116", fill="#F2F6E8", pen="1.5"),
    "private": _g("#00A4A6", fill="#E6F6F7", pen="1.5"),
    "isolated": _g("#147EBA", fill="#E9F3FA", pen="1.5"),
    "layer": _g("#7D8998", fill="#FAFAFA", style="rounded", pen="1"),
    "security": _g("#DD344C", fill="#FFFFFF", style="rounded,dashed", pen="1.5"),
    "external": _g("#545B64", fill="#F4F4F4", style="rounded", pen="1.5"),
    "trust": _g("#D13212", fill="#FFFFFF", style="dashed", pen="2.5"),
    "legend": {**_g(BRAND_BORDER, fill="#FFFFFF", style="rounded", pen="1.5"), "fontname": BRAND_BODY_FONT},
}

_E = {"fontname": FONT, "fontsize": "10", "fontcolor": AWS_INK, "arrowsize": "0.8", "penwidth": "1.4"}
EDGE = {
    "sync": {**_E, "color": AWS_INK},
    "async": {**_E, "color": "#E7157B", "style": "dashed"},
    "egress": {**_E, "color": "#DD344C"},
    "ext": {**_E, "color": "#545B64"},
    "mgmt": {**_E, "color": "#7D8998", "style": "dotted", "constraint": "false"},
}
COLUMN = {"rank": "same"}  # merge into a cluster's graph_attr to stack its nodes in one column

DIAGRAM_ATTRS = {
    "bgcolor": "white",
    "pad": "0.6",
    "nodesep": "0.7",
    "ranksep": "1.1",
    "splines": "ortho",
    "fontname": FONT,
    "fontsize": "22",
    "labelloc": "t",
    "newrank": "true",  # lets rank=same work inside clusters (column layout)
    "forcelabels": "true",
}


def legend_html() -> str:
    rows = [
        ("#232F3E", "solid", "Synchronous request (HTTPS / SQL over TLS)"),
        ("#E7157B", "dashed", "Asynchronous message or event (SQS / EventBridge)"),
        ("#DD344C", "solid", "Internet egress via NAT + Network Firewall allowlist"),
        ("#545B64", "solid", "External system interaction"),
        ("#7D8998", "dotted", "Management / telemetry"),
    ]
    cells = "".join(
        f'<tr><td><font color="{c}">{"━━━▶" if s == "solid" else ("╍╍╍▶" if s == "dashed" else "┈┈┈▶")}</font></td>'
        f'<td align="left"><font face="{BRAND_BODY_FONT}" color="{BRAND_NAVY}">{html.escape(t)}</font></td></tr>'
        for c, s, t in rows)
    return (f'<<table border="0" cellborder="0" cellpadding="3"><tr><td colspan="2" align="left">'
            f'<font face="{BRAND_HEADING_FONT}" point-size="14" color="{BRAND_NAVY}"><b>Legend</b></font></td></tr>'
            f'{cells}<tr><td colspan="2" align="left"><font face="{BRAND_BODY_FONT}" point-size="10" color="{BRAND_SLATE}">Numbered badges = flows described in the architecture walkthrough</font></td></tr></table>>')


def embed_svg_images(svg_path: Path) -> None:
    """Graphviz writes absolute file paths for node images; inline them as data URIs."""
    text = svg_path.read_text(encoding="utf-8")

    def repl(m: re.Match) -> str:
        attr, path = m.group(1), m.group(2)
        p = Path(html.unescape(path))
        if not p.is_file():
            return m.group(0)
        data = base64.b64encode(p.read_bytes()).decode()
        return f'{attr}="data:image/png;base64,{data}"'

    text = re.sub(r'((?:xlink:)?href)="([^"]+\.png)"', repl, text)
    svg_path.write_text(text, encoding="utf-8")


# ---- draw.io (mxGraph) writer ---------------------------------------------------------------------

_DRAWIO_GROUP = {
    "aws_cloud": "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_aws_cloud_alt;strokeColor=#232F3E;fillColor=none;fontColor=#232F3E;dashed=0;",
    "region": "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_region;strokeColor=#147EBA;fillColor=none;fontColor=#147EBA;dashed=1;",
    "vpc": "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_vpc2;strokeColor=#8C4FFF;fillColor=none;fontColor=#8C4FFF;dashed=0;",
    "public": "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor=#7AA116;fillColor=#F2F6E8;fontColor=#248814;dashed=0;",
    "private": "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor=#00A4A6;fillColor=#E6F6F7;fontColor=#147EBA;dashed=0;",
    "isolated": "shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor=#147EBA;fillColor=#E9F3FA;fontColor=#147EBA;dashed=0;",
    "layer": "rounded=1;arcSize=3;strokeColor=#7D8998;fillColor=#FAFAFA;fontColor=#232F3E;dashed=0;",
    "security": "rounded=1;arcSize=3;strokeColor=#DD344C;fillColor=none;fontColor=#DD344C;dashed=1;",
    "external": "rounded=1;arcSize=3;strokeColor=#545B64;fillColor=#F4F4F4;fontColor=#232F3E;dashed=0;",
    "legend": "rounded=1;arcSize=3;strokeColor=#D5DBE4;fillColor=#FFFFFF;fontColor=#0B1B33;fontFamily=Space Grotesk;align=left;spacingLeft=10;",
}
_GROUP_COMMON = "points=[[0,0],[0.25,0],[0.5,0],[0.75,0],[1,0],[1,0.25],[1,0.5],[1,0.75],[1,1],[0.75,1],[0.5,1],[0.25,1],[0,1],[0,0.75],[0,0.5],[0,0.25]];outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=13;fontStyle=1;container=0;verticalAlign=top;align=left;spacingLeft=30;"
_ICON = ("sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;strokeColor=#ffffff;dashed=0;"
         "verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;"
         "pointerEvents=1;whiteSpace=wrap;")
_EDGE = {
    "sync": "strokeColor=#232F3E;",
    "async": "strokeColor=#E7157B;dashed=1;",
    "egress": "strokeColor=#DD344C;",
    "ext": "strokeColor=#545B64;",
    "mgmt": "strokeColor=#7D8998;dashed=1;dashPattern=1 3;",
}


class Drawio:
    def __init__(self, name: str, width: int = 2400, height: int = 1500):
        self.name, self.width, self.height = name, width, height
        self.cells: list[str] = []
        self._n = 0
        self.dy = 0  # vertical offset for content placed after the title block

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}{self._n}"

    def group(self, title: str, kind: str, x: int, y: int, w: int, h: int, subtitle: str = "") -> str:
        cid = self._id("g")
        value = f"{escape(title)}" + (f"<br><span style='font-weight:normal;font-size:11px'>{escape(subtitle)}</span>" if subtitle else "")
        style = _DRAWIO_GROUP[kind] + _GROUP_COMMON + ("spacingLeft=10;" if kind in ("layer", "security", "external", "legend") else "")
        self.cells.append(f'<mxCell id="{cid}" value="{escape(value, {chr(34): "&quot;"})}" style="{style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x}" y="{y + self.dy}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def icon(self, role: str, service: str, shape: str, fill: str, x: int, y: int, size: int = 56,
             resource: bool = True) -> str:
        """``shape`` is an mxgraph.aws4 icon name. Resource icons use resIcon; product shapes use shape=."""
        cid = self._id("n")
        shape_style = (f"shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.{shape};fillColor={fill};"
                       if resource else f"shape=mxgraph.aws4.{shape};fillColor={fill};strokeColor=none;")
        value = f"<b>{escape(role)}</b>" + (f"<br>{escape(service)}" if service else "")
        self.cells.append(f'<mxCell id="{cid}" value="{escape(value, {chr(34): "&quot;"})}" style="{_ICON}{shape_style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x}" y="{y + self.dy}" width="{size}" height="{size}" as="geometry"/></mxCell>')
        return cid

    def image(self, png: Path, x: int, y: int, size: int) -> str:
        """Embedded PNG (draw.io stores images as data URIs without ';base64')."""
        cid = self._id("i")
        data = base64.b64encode(png.read_bytes()).decode()
        style = f"shape=image;aspect=fixed;imageAspect=0;verticalLabelPosition=bottom;image=data:image/png,{data};"
        self.cells.append(f'<mxCell id="{cid}" value="" style="{style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x}" y="{y}" width="{size}" height="{size}" as="geometry"/></mxCell>')
        return cid

    def title(self, title: str, subtitle: str, x: int = 20, y: int = 10) -> None:
        """Brand title block: mark (64 px), Space Grotesk navy title, Inter subtitle, orange rule."""
        self.image(BRAND_MARK_PNG, x, y, 64)
        style = (f"text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontFamily={BRAND_HEADING_FONT};"
                 f"fontSize=24;fontStyle=1;fontColor={BRAND_NAVY};")
        value = escape(f"{title}<br><span style='font-family:{BRAND_BODY_FONT};font-size:13px;font-weight:normal;"
                       f"color:{BRAND_SLATE}'>{subtitle}</span>", {chr(34): "&quot;"})
        cid = self._id("t")
        self.cells.append(f'<mxCell id="{cid}" value="{value}" style="{style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x + 76}" y="{y + 4}" width="1500" height="60" as="geometry"/></mxCell>')
        rid = self._id("r")
        self.cells.append(f'<mxCell id="{rid}" value="" style="rounded=0;strokeColor=none;fillColor={BRAND_ORANGE};" '
                          f'vertex="1" parent="1"><mxGeometry x="{x}" y="{y + 70}" width="1576" height="4" as="geometry"/></mxCell>')

    def box(self, role: str, detail: str, x: int, y: int, w: int = 200, h: int = 56) -> str:
        cid = self._id("b")
        value = f"<b>{escape(role)}</b><br><span style='font-size:10px'>{escape(detail)}</span>"
        style = "rounded=1;whiteSpace=wrap;html=1;strokeColor=#545B64;fillColor=#FFFFFF;fontColor=#232F3E;fontSize=11;"
        self.cells.append(f'<mxCell id="{cid}" value="{escape(value, {chr(34): "&quot;"})}" style="{style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x}" y="{y + self.dy}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def text(self, value: str, x: int, y: int, w: int, h: int, font: str | None = None) -> str:
        cid = self._id("t")
        style = "text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontSize=11;fontColor=#232F3E;" + (
            f"fontFamily={font};" if font else "")
        self.cells.append(f'<mxCell id="{cid}" value="{escape(value, {chr(34): "&quot;"})}" style="{style}" vertex="1" parent="1">'
                          f'<mxGeometry x="{x}" y="{y + self.dy}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def edge(self, src: str, dst: str, text: str, kind: str = "sync", exit_: str = "", entry: str = "") -> str:
        cid = self._id("e")
        style = (f"edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;endArrow=block;endFill=1;"
                 f"strokeWidth=1.5;fontSize=10;fontColor=#232F3E;labelBackgroundColor=#FFFFFF;{_EDGE[kind]}{exit_}{entry}")
        self.cells.append(f'<mxCell id="{cid}" value="{escape(text, {chr(34): "&quot;"})}" style="{style}" edge="1" parent="1" source="{src}" target="{dst}">'
                          f'<mxGeometry relative="1" as="geometry"/></mxCell>')
        return cid

    def write(self, path: Path) -> None:
        body = "".join(self.cells)
        xml = (f'<mxfile host="exposurecatalyst-docs" type="device"><diagram id="{self.name}" name="{escape(self.name)}">'
               f'<mxGraphModel dx="{self.width}" dy="{self.height}" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" '
               f'arrows="1" fold="1" page="1" pageScale="1" pageWidth="{self.width}" pageHeight="{self.height}" background="#FFFFFF" math="0" shadow="0">'
               f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root></mxGraphModel></diagram></mxfile>')
        path.write_text(xml, encoding="utf-8")

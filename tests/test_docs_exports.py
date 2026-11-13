"""Documentation exports: MkDocs → Pandoc conversion, guide selection and the role-filtered download API."""

from __future__ import annotations

import json

import pytest

from exposurecatalyst.docs import export
from exposurecatalyst.docs.guides import GUIDES, GUIDES_BY_ID, export_filename


def _ctx(fmt="docx", pages=None):
    return export.Context(fmt, pages or {"a/page.md": "page-a-page", "b/other.md": "page-b-other"})


def test_admonition_becomes_callout_div_and_headings_are_demoted():
    lines = ['!!! warning "Implementation status"', "    Body text.", "", "    ## Inner", "", "After"]
    out = "\n".join(export._admonitions(lines))
    assert '::: {.admonition .warning custom-style="Callout"}' in out
    assert "**Implementation status**" in out and "**Inner**" in out and "## Inner" not in out
    assert out.rstrip().endswith("After")


def test_admonition_inside_code_fence_is_left_alone():
    lines = ["```", '!!! note "x"', "    y", "```"]
    assert export._admonitions(lines) == lines


def test_figure_keeps_caption_and_drops_download_links():
    md = ('<figure markdown>\n  [![Alt](../assets/x.svg)](../assets/x.svg)\n  <figcaption>Figure 3. VPC &amp; subnets. '
          'Downloads: <a href="x.png">PNG</a></figcaption>\n</figure>')
    assert export._figures(md).strip() == "![Figure 3. VPC & subnets.](../assets/x.svg)"


def test_links_become_internal_anchors_or_plain_text():
    text = ("See [other](monitoring.md#section), [here](#local), [site](https://example.org/x), "
            "[gone](../c/missing.md) and [png](../assets/diagrams/dr.png).")
    pages = {"operations/runbooks.md": "page-rb", "operations/monitoring.md": "page-mon"}
    out = export._links(text, "operations/runbooks.md", _ctx(pages=pages))
    assert "[other](#page-mon)" in out
    assert "[here](#page-rb)" in out
    assert "[site](https://example.org/x)" in out
    assert " gone " in out and "png." in out and "missing.md" not in out


def test_first_h1_gets_page_anchor_and_later_h1_is_demoted():
    out = export._headings(["# Title", "```", "# shell comment", "```", "# Second"], "page-x")
    assert out == ["# Title {#page-x}", "```", "# shell comment", "```", "## Second"]


def test_docx_uses_png_render_for_svg_diagrams():
    out = export._images("![d](../assets/diagrams/dr.svg)", "operations/disaster-recovery.md", _ctx("docx"))
    assert out == "![d](docs/assets/diagrams/dr.png)"
    out = export._images("![d](../assets/diagrams/dr.svg)", "operations/disaster-recovery.md", _ctx("html"))
    assert out == "![d](docs/assets/diagrams/dr.svg)"


def test_missing_image_fails_the_build():
    with pytest.raises(SystemExit):
        export._images("![x](nope.png)", "index.md", _ctx())


def test_guides_follow_nav_and_every_page_converts():
    nav = export.nav_pages()
    every = {p for _, p in nav}
    assert export.guide_pages(GUIDES_BY_ID["full"], nav) == list(dict.fromkeys(p for _, p in nav))
    security = export.guide_pages(GUIDES_BY_ID["security"], nav)
    assert "security/threat-model.md" in security and "operations/disaster-recovery.md" in security
    assert "admin-guide/smtp.md" not in security
    user = export.guide_pages(GUIDES_BY_ID["user"], nav)
    assert "user-guide/advisories.md" in user and not any(p.startswith("admin-guide/") for p in user)
    for g in GUIDES:  # every extra page named by a guide exists in the nav
        assert set(g.pages) <= every, g.id
    for fmt in ("docx", "html"):
        md = export.combined_markdown(GUIDES_BY_ID["full"], fmt, nav)
        assert "```mermaid" not in md and "<figure" not in md and "--8<--" not in md and "!!! " not in md


def test_mermaid_blocks_all_have_committed_renders():
    for h in export.mermaid_sources():
        for ext in ("svg", "png"):
            assert (export.MERMAID_OUT / f"{h}.{ext}").is_file(), f"run `python -m exposurecatalyst.docs mermaid` ({h})"


# --------------------------------------------------------------------------------------------- API
@pytest.fixture
def exports_dir(settings, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "docs_exports_dir", tmp_path)
    guides = []
    for g in GUIDES:
        files = {}
        for fmt in ("docx", "html"):
            (tmp_path / export_filename(g.id, fmt)).write_bytes(b"x" * 10)
            files[fmt] = {"name": export_filename(g.id, fmt), "size": 10}
        guides.append({"id": g.id, "title": g.title, "files": files})
    (tmp_path / "manifest.json").write_text(json.dumps({"version": "1.0.0", "date": "2026-11-13",
                                                        "classification": "Internal", "guides": guides}))
    return tmp_path


@pytest.mark.parametrize(("role", "expected"), [
    ("Viewer", {"user"}),
    ("Auditor", {"user", "security"}),
    ("Admin", {"user", "admin", "security", "full"}),
])
def test_downloads_are_filtered_by_role(login, exports_dir, role, expected):
    c = login(role)
    body = c.get("/api/help/downloads").json()
    assert {g["id"] for g in body["guides"]} == expected
    assert body["version"] == "1.0.0"
    for gid in {"user", "admin", "security", "full"}:
        r = c.get(f"/api/help/downloads/{gid}/docx")
        assert r.status_code == (200 if gid in expected else 404), (role, gid)
        if r.status_code == 200:
            assert r.headers["content-disposition"].startswith("attachment")


def test_html_export_is_always_an_attachment(login, exports_dir):
    r = login("Viewer").get("/api/help/downloads/user/html")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_download_rejects_unknown_guide_format_and_traversal(login, exports_dir):
    c = login("Admin")
    for url in ("/api/help/downloads/nope/docx", "/api/help/downloads/user/pdf",
                "/api/help/downloads/..%2Fmanifest/json"):
        assert c.get(url).status_code == 404


def test_downloads_empty_when_not_built(login, settings, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "docs_exports_dir", tmp_path / "missing")
    assert login("Admin").get("/api/help/downloads").json()["guides"] == []


def test_downloads_require_login(client):
    assert client.get("/api/help/downloads").status_code == 401
    assert client.get("/api/help/downloads/user/docx").status_code == 401

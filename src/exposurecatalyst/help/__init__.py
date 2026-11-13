"""In-app help, rendered from the same Markdown files that build the documentation site.

Front matter keys:  id, title, page (route), permission (needed to see the page at all),
                    summary, keywords, docs (path under /docs for "Learn more").
Body blocks wrapped in ``<!-- requires: perm[,perm] -->`` … ``<!-- /requires -->`` are removed for
users lacking *any* of the listed permissions, so admin-only steps never reach Viewers.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import frontmatter
import yaml

_REQUIRES = re.compile(r"<!--\s*requires:\s*([\w:,\s-]+?)\s*-->(.*?)<!--\s*/requires\s*-->", re.DOTALL)
_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class HelpPage:
    id: str
    title: str
    page: str | None
    permission: str | None
    summary: str
    keywords: tuple[str, ...]
    docs: str | None
    body: str


def filter_body(body: str, perms: set[str]) -> str:
    def repl(m: re.Match) -> str:
        needed = {p.strip() for p in m.group(1).split(",") if p.strip()}
        return m.group(2) if needed <= perms else ""

    return re.sub(r"\n{3,}", "\n\n", _REQUIRES.sub(repl, body)).strip()


class HelpRepository:
    def __init__(self, root: Path):
        self.root = root
        self._lock = threading.Lock()
        self._stamp: float | None = None
        self._pages: dict[str, HelpPage] = {}
        self._tooltips: dict[str, Any] = {}

    def _load(self) -> None:
        files = sorted(self.root.glob("*.md")) + [self.root / "tooltips.yml"]
        stamp = max((f.stat().st_mtime for f in files if f.exists()), default=0.0)
        with self._lock:
            if stamp == self._stamp:
                return
            pages = {}
            for f in self.root.glob("*.md"):
                post = frontmatter.load(f)
                pid = str(post.get("id") or f.stem)
                pages[pid] = HelpPage(
                    id=pid,
                    title=str(post.get("title", pid)),
                    page=post.get("page"),
                    permission=post.get("permission"),
                    summary=str(post.get("summary", "")),
                    keywords=tuple(post.get("keywords", []) or []),
                    docs=post.get("docs"),
                    body=post.content,
                )
            tips_file = self.root / "tooltips.yml"
            self._tooltips = yaml.safe_load(tips_file.read_text()) if tips_file.exists() else {}
            self._pages, self._stamp = pages, stamp

    def visible(self, perms: set[str]) -> list[HelpPage]:
        self._load()
        return sorted((p for p in self._pages.values() if not p.permission or p.permission in perms),
                      key=lambda p: p.title)

    def get(self, page_id: str, perms: set[str]) -> HelpPage | None:
        self._load()
        p = self._pages.get(page_id)
        if p is None or (p.permission and p.permission not in perms):
            return None
        return p

    def render(self, page: HelpPage, perms: set[str]) -> dict[str, Any]:
        return {"id": page.id, "title": page.title, "summary": page.summary, "docs": page.docs,
                "page": page.page, "markdown": filter_body(page.body, perms)}

    def search(self, query: str, perms: set[str], limit: int = 20) -> list[dict[str, Any]]:
        terms = _WORD.findall(query.lower())[:10]
        if not terms:
            return []
        hits = []
        for p in self.visible(perms):
            body = filter_body(p.body, perms)
            hay_title = f"{p.title} {' '.join(p.keywords)}".lower()
            hay = body.lower()
            score = sum(hay_title.count(t) * 5 + hay.count(t) for t in terms)
            if score:
                idx = min((hay.find(t) for t in terms if hay.find(t) >= 0), default=0)
                snippet = body[max(0, idx - 60): idx + 140].replace("\n", " ").strip()
                hits.append({"id": p.id, "title": p.title, "snippet": snippet, "score": score})
        return sorted(hits, key=lambda h: -h["score"])[:limit]

    def tooltips(self) -> dict[str, Any]:
        self._load()
        return self._tooltips

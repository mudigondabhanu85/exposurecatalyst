"""A deliberately small JSONPath subset for field mapping (no filters, no script expressions):

    $                     the record itself            $.a.b / a.b       nested keys
    $.items[*]            every element                $.items[0]        one element
    $['key with dots']    quoted key                   $..name           NOT supported (explicit paths only)

`find(obj, path)` returns every match (lists flattened by [*]); `first` returns the first non-empty one.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(r"""\.([A-Za-z0-9_\-:$@]+)|\[\s*'([^']*)'\s*\]|\[\s*"([^"]*)"\s*\]|\[\s*(\*|-?\d+)\s*\]""")
MAX_PATH = 300


class PathError(ValueError):
    pass


def parse(path: str) -> list[str | int]:
    if not isinstance(path, str) or not path.strip():
        raise PathError("empty path")
    p = path.strip()
    if len(p) > MAX_PATH:
        raise PathError("path too long")
    if p.startswith("$"):
        p = p[1:]
    elif not p.startswith((".", "[")):
        p = "." + p
    out: list[str | int] = []
    pos = 0
    while pos < len(p):
        m = _TOKEN.match(p, pos)
        if m is None:
            raise PathError(f"unsupported JSONPath syntax at '{p[pos : pos + 20]}' (use $.a.b, [n], [*], ['key'])")
        key = m.group(1) or m.group(2) or m.group(3)
        idx = m.group(4)
        if key is not None:
            out.append(key)
        elif idx == "*":
            out.append("*")
        else:
            out.append(int(idx))
        pos = m.end()
    return out


def find(obj: Any, path: str) -> list[Any]:
    current = [obj]
    for step in parse(path):
        nxt: list[Any] = []
        for node in current:
            if step == "*":
                if isinstance(node, list):
                    nxt.extend(node)
                elif isinstance(node, dict):
                    nxt.extend(node.values())
            elif isinstance(step, int):
                if isinstance(node, list) and -len(node) <= step < len(node):
                    nxt.append(node[step])
            elif isinstance(node, dict) and step in node:
                nxt.append(node[step])
        current = nxt
    return current


def first(obj: Any, path: str) -> Any:
    for v in find(obj, path):
        if v not in (None, "", [], {}):
            return v
    return None

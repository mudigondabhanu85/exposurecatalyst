"""Render every diagram module in this folder → SVG (icons embedded), 300-DPI PNG, and .drawio.

Usage: python _render_all.py <output-dir>     (needs Graphviz `dot` + the `diagrams` package)
Exit code is non-zero if any diagram fails, so CI fails the docs build.
"""

from __future__ import annotations

import importlib
import sys
import traceback
from pathlib import Path

from _aws_style import embed_svg_images

HERE = Path(__file__).parent


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    failures = 0
    for script in sorted(HERE.glob("*.py")):
        if script.name.startswith("_"):
            continue
        name = script.stem
        try:
            mod = importlib.import_module(name)
            mod.build(out, "svg", 96)
            embed_svg_images(out / f"{name}.svg")
            mod.build(out, "png", 300)
            mod.drawio(out / f"{name}.drawio")
            print(f"rendered {name}: svg, png@300dpi, drawio")
        except Exception:  # noqa: BLE001
            failures += 1
            traceback.print_exc()
            print(f"FAILED {name}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else HERE.parent / "assets" / "diagrams")))

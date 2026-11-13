# Renders docs/diagrams/*.py (mingrammer "diagrams" + Graphviz). Used by `make diagrams` / CI.
# Build context: docs/assets/fonts (brand fonts, OFL) — converted to TTF so Graphviz/fontconfig can use them
# for the brand title block and legend.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends graphviz fonts-dejavu-core fontconfig \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "diagrams==0.24.4" "fonttools[woff]==4.55.0"
COPY *.woff2 /tmp/fonts/
# Convert woff2 → TTF. The @fontsource Space Grotesk files name their family "Space Grotesk Light"
# (variable-font instance naming); normalise name IDs 1/16 so fontconfig matches "Space Grotesk".
RUN mkdir -p /usr/local/share/fonts/brand && cat > /tmp/conv.py <<'PY'
import sys
from fontTools.ttLib import TTFont
t = TTFont(sys.argv[1]); t.flavor = None
for rec in t["name"].names:
    if rec.nameID in (1, 16) and "Space Grotesk" in rec.toUnicode():
        rec.string = "Space Grotesk"
t.save(sys.argv[2])
PY
RUN for f in /tmp/fonts/*.woff2; do python /tmp/conv.py "$f" "/usr/local/share/fonts/brand/$(basename "$f" .woff2).ttf"; done \
    && fc-cache -f && fc-match "Space Grotesk:bold" | grep -q -i grotesk && fc-match Inter | grep -q -i inter
RUN useradd -m render
USER render

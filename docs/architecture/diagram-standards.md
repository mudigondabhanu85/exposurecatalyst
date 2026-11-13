# Diagram standards & pipeline

All architecture, deployment and data-flow diagrams follow AWS reference-architecture conventions.

## Conventions

- **Official AWS Architecture Icons** for every AWS service, bundled with the `diagrams` package and the
  draw.io `mxgraph.aws4` library. Labels show the **role in bold** with the AWS service name beneath.
- **Boundaries**: AWS Cloud → Region (dashed blue) → VPC (purple) → subnets. Subnets are public (green),
  private (teal) or isolated (blue). Layers are labeled: Edge, Application/Logic, Messaging, Data,
  Security & Observability.
- **External systems** sit in grey *Users & Identity*, *External Sources* and *Outbound Services* panels
  outside the AWS Cloud boundary.
- **Every arrow is directional and labeled** with what flows and how. Numbered black badges match the
  numbered-flow table in each page's walkthrough.
- **Edge semantics**: solid dark = synchronous; dashed magenta = async message or event; red = internet
  egress through Network Firewall; grey = external system; dotted = management or telemetry.
- Left-to-right flow, white background, legend included. Trust boundaries in DFDs are red dashed lines
  (Phase 6).

## Formats

| Format | Path | Use |
|---|---|---|
| Python source | `docs/diagrams/<name>.py` | Single source, reviewed in PRs, regenerated in CI |
| SVG (icons embedded) | `docs/assets/diagrams/<name>.svg` | HTML docs, standalone HTML |
| PNG 300 DPI | `docs/assets/diagrams/<name>.png` | DOCX exports, slides |
| draw.io | `docs/assets/diagrams/<name>.drawio` | Manual refinement with real AWS group shapes (Cloud, Region flag, VPC) |

The SVG/PNG are laid out automatically by Graphviz. The `.drawio` is generated from a hand-placed grid in the
same Python module, so it's landscape and pixel-aligned, and opens in diagrams.net with the AWS 2024 shape
library already applied.

## Regenerating

```bash
make diagrams          # uses local Graphviz, or the Docker image docker/diagrams.Dockerfile if `dot` is absent
python -m exposurecatalyst.docs build --docker   # full docs build, forcing Docker rendering
```

The renderer exits non-zero if any diagram fails, and the docs build then verifies that every expected output
exists, so CI fails on a broken diagram.

## Adding a diagram

1. Create `docs/diagrams/<name>.py` exposing `build(out_dir, fmt, dpi)` and `drawio(path)`, using the helpers
   in `docs/diagrams/_aws_style.py`: `label()`, `GROUP`, `EDGE`, `COLUMN`, `Drawio`.
2. Run `make diagrams` and embed `../assets/diagrams/<name>.svg` in the relevant page, with a numbered-flow
   walkthrough.

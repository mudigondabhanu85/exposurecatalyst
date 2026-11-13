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
- Left-to-right flow, white background, legend included. Trust boundaries in DFDs are red dashed lines.

## Formats

| Format | Path | Use |
|---|---|---|
| Python source | `docs/diagrams/<name>.py` | Single source, reviewed in PRs, regenerated in CI |
| SVG (icons embedded) | `docs/assets/diagrams/<name>.svg` | HTML docs, standalone HTML |
| PNG 300 DPI | `docs/assets/diagrams/<name>.png` | DOCX exports, slides |
| draw.io | `docs/assets/diagrams/<name>.drawio` | Manual refinement with real AWS group shapes (Cloud, Region flag, VPC) |

The SVG/PNG are laid out automatically by Graphviz. For the high-level AWS and identity diagrams the `.drawio`
is generated from a hand-placed grid in the same Python module (landscape, pixel-aligned). The network, DR,
DFD and component diagrams set `AUTO_DRAWIO = True`: their `.drawio` is built from Graphviz's own layout
(`dot -Tjson`), so it matches the SVG exactly. All open in diagrams.net with the AWS 2024 shape library.

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

## Documentation exports (DOCX and standalone HTML)

`python -m exposurecatalyst.docs build` (or `make docs`) also exports four guides into `dist/docs/exports/`:

| Guide | Contents | Who can download it in the app |
|---|---|---|
| User Guide | Home, user guide, user help topics | Everyone |
| Administrator Guide | Installation, admin guide, integrations, reference, operations, settings help | Any admin permission |
| Security & Architecture Guide | Architecture, security, DR, monitoring, RBAC matrix | Admins and Auditors (`audit:view`) |
| Complete Guide | Every page | `settings:manage` |

Each guide is produced as:

- **DOCX** via Pandoc and a branded `reference.docx` (generated at build time from Pandoc's default): cover
  page with the logo, version, date and classification; table of contents; numbered headings; header and
  footer with *Page X of Y*; 300-DPI PNG diagrams; wide diagrams on their own landscape pages. Word refreshes
  the TOC and page count when the file is opened (accept the *update fields* prompt).
- **Standalone HTML**: a single file with CSS, brand fonts, logo and SVG diagrams embedded. Works offline.

Mermaid blocks are rendered with mermaid-cli into `docs/assets/mermaid/<hash>.{svg,png}` and committed
(`python -m exposurecatalyst.docs mermaid --docker`). CI fails if a block has no committed render. Pandoc runs
locally if version 3 or later is installed, otherwise in the pinned `pandoc/core` Docker image. The
application image builds the exports in its docs stage, and they're served from **Help Center → Download
documentation** (`GET /api/help/downloads`), always as attachments.

Body text uses Inter and headings Space Grotesk (both OFL, in `docs/assets/fonts`). Install them on machines
that open the DOCX, or Word substitutes a default font.

```bash
make docs-exports      # only the DOCX / HTML guides
```

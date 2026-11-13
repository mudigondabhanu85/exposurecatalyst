# Brand

ExposureCatalyst's identity is defined by the brand kit in the repository at **`brand/`**. Its
`brand/README.md` is the source of truth and is reproduced at the bottom of this page. Use the asset files
exactly as provided. Don't redraw the logo, re-type the wordmark, recolor, stretch or add effects.

## Logos

<div class="ec-logo-panel" markdown>
![ExposureCatalyst](assets/brand/logo-light.svg){ width="320" }
</div>
<div class="ec-logo-panel ec-logo-panel--dark" markdown>
![ExposureCatalyst](assets/brand/logo-dark.svg){ width="320" }
</div>

| Asset | Where it is used |
|---|---|
| `svg/logo-dark-wordmark.svg` | App top bar (navy), 36 px tall |
| `svg/mark-simple-dark.svg` | App top bar on narrow screens, help drawer header (< 64 px) |
| `svg/mark-dark.svg` | Help Center banner (64 px) |
| `svg/logo-light.svg` | Login page; this documentation's header (light theme) |
| `svg/logo-dark.svg` | Documentation header (dark theme) |
| `svg/mark-light.svg` | Loading, 403, 404 and 500 screens (64 px); documentation favicon |
| `favicon/favicon.svg`, `favicon.ico`, `apple-touch-icon.png`, `icon-192/512.png` | Browser tab, iOS home screen, PWA manifest, Swagger/ReDoc |
| `png/og-image-1200x630.png` | Open Graph / Twitter link previews |
| `png/logo-light-wordmark@2x.png` | Advisory email header (displayed at 211×40, sharp on retina), Excel Summary sheet, SMTP test email |
| `png/mark-light-512.png` | Architecture diagram title block (64 px) |
| `png/app-icon-512.png` | **Okta app tile logo**: upload it in Okta Admin → Applications → *ExposureCatalyst* → General → App logo (used by the Okta setup guide in Phase 4) |

## Colors

| Token | Hex | Use |
|---|---|---|
| <span class="ec-swatch" style="background:#0B1B33"></span>`--ec-navy` | `#0B1B33` | Primary brand / ink, top bar, primary buttons, Excel header rows |
| <span class="ec-swatch" style="background:#E8541A"></span>`--ec-orange` | `#E8541A` | Accent on light: focus rings, active indicators, email header rule. **Not for body-size text** (3.7:1 on white) |
| <span class="ec-swatch" style="background:#FF7A3D"></span>`--ec-orange-bright` | `#FF7A3D` | Accent on navy/dark (6.7:1 on navy) |
| <span class="ec-swatch" style="background:#4A5568"></span>`--ec-slate` | `#4A5568` | Secondary text on light (7.5:1 on white) |
| <span class="ec-swatch" style="background:#B8C2D3"></span>`--ec-slate-light` | `#B8C2D3` | Secondary text on navy |
| <span class="ec-swatch" style="background:#F7F8FA"></span>`--ec-surface` | `#F7F8FA` | Page background |
| <span class="ec-swatch" style="background:#EEF1F5"></span>`--ec-surface-alt` | `#EEF1F5` | Cards, table headers, footer bands |
| <span class="ec-swatch" style="background:#D5DBE4"></span>`--ec-border` | `#D5DBE4` | Borders, dividers |

### Severity palette (not brand colors)

Orange is a brand accent only. Severity uses its own palette, and every badge also shows its text label and
an edge marker, so color is never the only signal:

| Severity | Background / text | Contrast |
|---|---|---|
| <span class="ec-swatch" style="background:#7A0F1C"></span>Critical | `#7A0F1C` / white | 11.0:1 |
| <span class="ec-swatch" style="background:#C21D2F"></span>High | `#C21D2F` / white | 5.9:1 |
| <span class="ec-swatch" style="background:#FCE38A"></span>Medium | `#FCE38A` / `#5C4200` | 7.8:1 |
| <span class="ec-swatch" style="background:#DCE9FB"></span>Low | `#DCE9FB` / `#14386B` | 9.8:1 |

## Typography

- **Space Grotesk** 500/700: page titles and headings (app, email headings, docs).
- **Inter** 400/500/600: body, tables, forms.

Both fonts are **self-hosted**: `@fontsource` in the app, `docs/assets/fonts` in the docs. The strict CSP
blocks third-party font hosts, and self-hosting avoids sending users' IP addresses to Google. Emails and
Excel name Inter/Space Grotesk with Arial/Calibri fallbacks, because recipients may not have the brand fonts
installed.

## Where brand values live in code

| Layer | File |
|---|---|
| App tokens | `frontend/src/brand/tokens.css` (copy of `brand/tokens/tokens.css` without the Google Fonts import), mapped in `frontend/tailwind.config.js` |
| App assets | Copied unmodified from `brand/assets` to `frontend/public/brand` by `frontend/scripts/sync-brand.mjs` |
| Email | `src/exposurecatalyst/advisories/templates/layout.html.j2`, `components.html.j2` (inline styles) |
| Excel | `src/exposurecatalyst/advisories/excel.py` |
| Docs | `docs/stylesheets/brand.css`, `mkdocs.yml`. Assets synced by `python -m exposurecatalyst.docs build` |
| Diagrams | Title block and legend in `docs/diagrams/_aws_style.py`. AWS icons and colors are unchanged |

??? abstract "brand/README.md (source of truth)"

    --8<-- "brand/README.md"

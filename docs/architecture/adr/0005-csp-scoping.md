# ADR-0005: Content Security Policy scoping

**Status:** Accepted · **Date:** 2026-11-13

## Context
The SPA should run under a strict CSP: no inline script or style, `frame-ancestors 'none'`. MkDocs Material
and Swagger UI rely on inline bootstrap scripts and CDN assets.

## Decision
- **Application** (`/`, `/api/*`): `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';
  frame-ancestors 'none'`. React code uses no `style=` attributes, and Markdown is rendered without raw HTML.
- **Docs and API explorer** (`/docs/*`, `/api/docs`, `/api/redoc`): allow `'unsafe-inline'` and the specific
  CDNs these tools need. Both serve static, build-time content. `/docs` requires an authenticated session,
  and Swagger can be disabled in production with `EXCAT_API_DOCS_ENABLED=false`.

## Consequences
- ✅ The interactive app, where untrusted CVE and news text is displayed, keeps the strict policy.
- ⚠️ The docs path has a weaker CSP. The risk is limited because it renders only our own build output.
  Revisit with nonce-based CSP if MkDocs Material adds support.

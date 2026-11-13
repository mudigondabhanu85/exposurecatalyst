# ADR-0004: Single-source help and documentation

**Status:** Accepted · **Date:** 2026-11-13

## Context
In-app help and published documentation tend to drift apart. Help must also respect RBAC, so a Viewer never
sees admin-only procedures.

## Decision
Help topics are Markdown files in `docs/help/`, with front matter for id, route, required permission and docs
link. The **same files** are rendered by MkDocs and served in-app by `/api/help/*`. Admin-only passages are
wrapped in `<!-- requires: perm -->…<!-- /requires -->` and stripped server-side for users who lack the
permission. These are invisible HTML comments in MkDocs. Tooltips come from `docs/help/tooltips.yml`.
Reference pages (configuration, RBAC matrix) are **generated from code** during the docs build.

## Consequences
- ✅ A single PR updates help and docs together. Code-derived pages can't drift.
- ✅ RBAC filtering happens server-side, never only in the UI.
- ⚠️ The published documentation site contains all content and is restricted to authenticated users.
  Audience-specific DOCX/HTML exports (Phase 6) are filtered by role.

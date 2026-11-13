# ADR-0002: Server-side sessions with session-bound CSRF tokens

**Status:** Accepted · **Date:** 2026-11-13

## Context
We need immediate revocation (logout, role change, deactivation), idle and absolute timeouts (ASVS V3), and
protection against token theft. JWTs in browser storage are exposed to XSS and can't be revoked without a
deny-list.

## Decision
- An opaque 256-bit random token in a `__Host-` cookie that is `HttpOnly; Secure; SameSite=Strict`. The DB
  stores only its **SHA-256**.
- Idle timeout of 30 minutes and absolute timeout of 8 hours, both configurable. Sessions are revoked on
  logout, password change, role change and deactivation.
- **CSRF**: a per-session random token stored on the session row, exposed to the SPA via a readable
  `__Host-` cookie and `/api/auth/me`, and required in `X-CSRF-Token` on every unsafe method. It's compared in
  constant time. An **Origin** check rejects cross-origin unsafe requests as defence in depth.

## Consequences
- ✅ Instant revocation, and a DB leak doesn't yield usable session tokens.
- ⚠️ One indexed DB lookup per request (cached by primary key). `last_seen_at` is written at most once a
  minute.
- SAML/OIDC (Phase 4) will create the same session type after assertion validation.

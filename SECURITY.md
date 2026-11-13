# Security policy

## Reporting a vulnerability

Please **do not** open public issues for security problems. Report them privately to the security team
through your organization's vulnerability disclosure channel, for example `security@<your-company-domain>`,
and include:

- affected version or commit, and the component (API endpoint, connector, UI page)
- reproduction steps or proof of concept, and impact
- any suggested remediation

We acknowledge reports within **2 business days**, give an initial assessment within **5 business days**,
and aim to fix critical issues within **30 days**. Reporters acting in good faith won't face legal action.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Scope highlights

Authentication and session handling, RBAC bypass, SSRF via configurable URLs, injection, XSS from upstream
CVE or news content, prompt injection reaching tools or data (Phase 5), secret exposure in logs or API
responses, and audit-log tampering.

See `docs/security/overview.md` for the implemented controls.

# ExposureCatalyst

**Vulnerability Intelligence & Advisory Platform.** ExposureCatalyst ingests new and updated CVEs from trusted
sources, correlates them with affected assets from your security and CTEM tools, and generates reviewable
stakeholder advisory emails.

!!! info "Single source of truth"
    This documentation is generated from the same Markdown that powers the in-app **?** help drawer, so the
    help and the docs can't drift apart. The build date is stamped in the footer of exported formats.

## Key features

| Tab | What it does | Status |
|---|---|---|
| **CVE Intelligence** | Normalized, de-duplicated CVEs from NVD, CISA KEV and FIRST EPSS, with per-field provenance, search, filters, saved searches, a timeline and source health | **Phase 1 ✅** |
| **Advisory Email Generator** | HTML advisories, an asset validation matrix, an Excel attachment, `.eml` / Copy for Outlook / SMTP delivery and an approval workflow | **Phase 2 ✅** |
| **Integrations** | Plugin connectors for Qualys, Tanium, Wiz, Zafran, ArmorCode, ServiceNow CMDB and more | **Phase 3 ✅** |
| **Identity** | Okta SAML 2.0, SailPoint group → role mapping (SCIM 2.0), alerts and scheduling | **Phase 4 ✅** (OIDC deferred) |
| **Security News & AI** | De-duplicated news feeds, a multi-provider AI layer with a redaction policy | **Phase 5 ✅** |
| **Hardening & exports** | Terraform, DR and network diagrams, threat model, runbooks, guided tours, DOCX/standalone HTML docs | Phase 6 |

## Roadmap

Delivery is phased. Each phase ships its own in-app help, documentation and diagrams.

1. **Phase 1.** Scaffold, DB models and migrations, local auth with MFA and RBAC, CVE
   Intelligence (NVD + KEV + EPSS), the help framework (drawer, tooltips, Help Center), the MkDocs skeleton,
   the diagram pipeline and the [high-level AWS architecture](architecture/high-level.md).
2. **Phase 2.** Advisory email generator, Excel export, `.eml` / Copy / SMTP delivery, manual
   entry, versioned templates with approval, and brand identity applied across the app, emails and exports.
3. **Phase 3.** Connector framework and the first six connectors, CVE asset correlation with CMDB
   enrichment, and an integration guide for each.
4. **Phase 4.** Okta SAML and SP metadata, SailPoint mapping and SCIM, alerts and scheduling,
   custom roles, setup wizards, identity flow and sequence diagrams.
5. **Phase 5 (this release).** Security News and the AI provider layer with AI features.
6. **Phase 6.** Hardening, Terraform, DR/network diagrams, STRIDE threat model, DFDs, runbooks, guided
   tours, DOCX and standalone HTML exports.

## Where to start

- **Analysts & approvers**: [CVE Intelligence](user-guide/cve-intelligence.md),
  [Advisories](user-guide/advisories.md)
- **Admins**: [Installation](getting-started/installation.md), [Users & RBAC](admin-guide/rbac.md),
  [SMTP](admin-guide/smtp.md), [Integrations](integrations/index.md), [Okta SSO](admin-guide/okta-saml.md),
  [SailPoint](admin-guide/sailpoint.md), [Alerts](admin-guide/alerts.md), [AI](admin-guide/ai.md),
  [Ingestion sources](admin-guide/ingestion-sources.md)
- **Security & architecture reviewers**: [AWS architecture](architecture/high-level.md),
  [Security overview](security/overview.md), [ADRs](architecture/adr/index.md)
- **Glossary**: [CVE, CVSS, EPSS, KEV, CWE, CPE, CTEM…](help/glossary.md)

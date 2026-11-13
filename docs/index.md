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
| **Advisory Email Generator** | HTML advisories, an asset validation matrix, an Excel attachment, `.eml` / Copy for Outlook / SMTP delivery and an approval workflow | Phase 2 |
| **Integrations** | Plugin connectors for Qualys, Tanium, Wiz, Zafran, ArmorCode, ServiceNow CMDB and more | Phase 3 |
| **Identity** | Okta SAML 2.0 / OIDC, SailPoint group → role mapping (SCIM 2.0), alerts and scheduling | Phase 4 |
| **Security News & AI** | De-duplicated news feeds, a multi-provider AI layer with a redaction policy | Phase 5 |
| **Hardening & exports** | Terraform, DR and network diagrams, threat model, runbooks, guided tours, DOCX/standalone HTML docs | Phase 6 |

## Roadmap

Delivery is phased. Each phase ships its own in-app help, documentation and diagrams.

1. **Phase 1 (this release).** Scaffold, DB models and migrations, local auth with MFA and RBAC, CVE
   Intelligence (NVD + KEV + EPSS), the help framework (drawer, tooltips, Help Center), the MkDocs skeleton,
   the diagram pipeline and the [high-level AWS architecture](architecture/high-level.md).
2. **Phase 2.** Advisory email generator, Excel export, `.eml` / Copy / SMTP delivery, manual entry.
3. **Phase 3.** Connector framework and the first six connectors, with an integration guide for each.
4. **Phase 4.** Okta SAML and SP metadata, SailPoint mapping, alerts and scheduling, setup wizards, identity
   flow diagram.
5. **Phase 5.** Security News and the AI provider layer.
6. **Phase 6.** Hardening, Terraform, DR/network diagrams, STRIDE threat model, DFDs, runbooks, guided
   tours, DOCX and standalone HTML exports.

## Where to start

- **Analysts**: [CVE Intelligence user guide](user-guide/cve-intelligence.md)
- **Admins**: [Installation](getting-started/installation.md), [Users & RBAC](admin-guide/rbac.md),
  [Ingestion sources](admin-guide/ingestion-sources.md)
- **Security & architecture reviewers**: [AWS architecture](architecture/high-level.md),
  [Security overview](security/overview.md), [ADRs](architecture/adr/index.md)
- **Glossary**: [CVE, CVSS, EPSS, KEV, CWE, CPE, CTEM…](help/glossary.md)

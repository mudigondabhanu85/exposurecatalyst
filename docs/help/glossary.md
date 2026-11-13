---
id: glossary
title: Glossary
summary: Definitions of vulnerability-management terms used throughout ExposureCatalyst.
keywords: [glossary, definitions, cve, cvss, epss, kev, cwe, cpe, ctem, sla, psirt]
docs: help/glossary/
---

| Term | Definition |
|---|---|
| **CVE** | *Common Vulnerabilities and Exposures*. A unique public identifier (`CVE-YYYY-NNNN+`) assigned to a disclosed vulnerability by a CVE Numbering Authority (CNA). |
| **CNA** | *CVE Numbering Authority*. An organization (often the vendor, e.g. Fortinet PSIRT) authorized to assign CVE IDs and publish the first record. |
| **NVD** | *National Vulnerability Database* (NIST). Enriches CVEs with CVSS scores, CWE and CPE applicability. |
| **CVSS** | *Common Vulnerability Scoring System*. A 0–10 severity score (versions 2.0, 3.0, 3.1, 4.0) with a vector describing how a flaw is exploited and its impact. It measures **severity, not risk**. |
| **CVSS vector** | Compact encoding of the metrics, e.g. `AV:N` (network attack vector), `PR:N` (no privileges), `UI:N` (no user interaction). |
| **EPSS** | *Exploit Prediction Scoring System* (FIRST). The estimated probability (0–1) that a CVE will be exploited in the wild in the next 30 days. Updated daily. |
| **EPSS percentile** | The share of all scored CVEs with an equal or lower EPSS. 0.99 means the top 1 %. |
| **KEV** | CISA's *Known Exploited Vulnerabilities* catalog: CVEs with reliable evidence of active exploitation. US federal agencies must remediate them by the listed **due date**. |
| **CWE** | *Common Weakness Enumeration*. The class of bug, e.g. `CWE-787` out-of-bounds write. |
| **CPE** | *Common Platform Enumeration*. A structured name for vendor/product/version, e.g. `cpe:2.3:o:fortinet:fortios:7.4.2`. |
| **CTEM** | *Continuous Threat Exposure Management*. A program that continuously scopes, discovers, prioritizes, validates and mobilizes remediation of exposures. |
| **PSIRT** | *Product Security Incident Response Team*. A vendor's team that publishes security advisories. |
| **SLA** | *Service Level Agreement*. Here, the remediation deadline by severity (e.g. Critical in 7 days). |
| **Exploit available** | A public exploit or proof-of-concept is referenced, or the CVE is in KEV. |
| **Provenance** | The source and timestamp of each field in a merged CVE record. |
| **Advisory ID** | `EXCAT-YYYY-NNNN`. A unique reference stamped on every advisory email, for tickets and replies. |
| **Validated = Yes** | In an advisory, a source (e.g. Qualys) that actually identified affected assets. Sources with zero hits show *No*. |
| **Break-glass account** | A local admin account with MFA, used when SSO is unavailable. |
| **RBAC** | *Role-Based Access Control*. Permissions are granted to roles, and roles to users or groups. |
| **SoD** | *Segregation of Duties*. For example, the person who approves an advisory isn't the person who drafted it. |

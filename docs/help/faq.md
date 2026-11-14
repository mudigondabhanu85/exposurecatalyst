---
id: faq
title: FAQ
summary: Frequently asked questions.
keywords: [faq, questions]
docs: help/faq/
---

**How fresh is the data?**
Each source refreshes every 60 minutes by default. NVD is fetched incrementally by *last-modified* time,
KEV only downloads when the catalog changes (ETag), and EPSS is checked once a day per CVE.

**Why is a CVE's severity UNKNOWN?**
NVD hasn't scored it yet (status *Awaiting Analysis* or *Received*). KEV listing and EPSS still apply.

**Which CVSS version is shown?**
By default v3.1, then v4.0, then v3.0, then v2.0. Within a version, NVD's *Primary* score wins. The detail
page lists every score. Admins can change the order with `EXCAT_CVSS_PREFERRED_VERSIONS`.

**Is high CVSS the same as high risk?**
No. Combine CVSS (severity) with EPSS (likelihood), KEV (known exploitation) and your own exposure
(affected assets).

**Does ExposureCatalyst send our data anywhere?**
Only where your administrators configure it: advisory emails go to the recipients you approve, alerts go to
the configured email, Slack or Teams destinations, and AI features (off by default) send redacted text to the
approved provider. Integrations are read-only lookups. Every outbound host is restricted by an egress
allowlist.

**I was signed out unexpectedly.**
Sessions end after 30 minutes of inactivity or 8 hours in total, and when an admin changes your roles.

# Security News

The Security News tab collects recent attacks and security news from trusted sources, groups the same story
across outlets, and links mentioned CVEs to CVE Intelligence.

## Sources (default)

| Category | Feeds |
|---|---|
| Government | CISA Cybersecurity Advisories |
| News | BleepingComputer, The Hacker News, SecurityWeek, Dark Reading, The Record, Krebs on Security, SANS ISC |
| Vendor threat intel | Palo Alto Unit 42, Cisco Talos, Google Threat Intelligence (Mandiant), Microsoft Threat Intelligence, CrowdStrike |

Feed URLs change occasionally. A failing feed shows *Failing* with its error in Settings → News feeds, and
admins can update or replace it.

!!! warning "CISA advisories feed and bot protection"
    `www.cisa.gov` is behind a CDN bot-management layer that can return **403 Access Denied** to server-side
    clients from some networks, even with a descriptive User-Agent. This was observed from a Docker container
    while the same request from a workstation succeeded. ExposureCatalyst does **not** attempt to evade
    bot protection. If the feed fails from your egress IPs, ask your network team to have them allowlisted
    with CISA/Akamai, or disable the feed. CISA **KEV** ingestion uses a different path and is unaffected.

## How stories are processed

1. **Fetch** every 30 minutes (`EXCAT_NEWS_INTERVAL_MINUTES`, or per-source in Settings → CVE Sources). Uses
   ETag/304 where supported.
2. **Parse** RSS 2.0 and Atom with a hardened XML parser. Documents with XML entities are rejected, and only
   `http(s)` links are kept.
3. **Store only** the headline, source, date, a short excerpt (≤ 300 characters, HTML removed) and the link.
   Full articles are **never** copied. Readers follow the link to the publisher.
4. **De-duplicate**: the same URL (ignoring `utm_*` tracking and `www.`) is stored once. Stories with similar
   headlines from different outlets within 3 days are **clustered** and shown once, with "also covered by".
5. **Enrich**: CVE IDs are extracted and linked, and topic tags are added (ransomware, zero-day,
   vulnerability, data-breach, phishing, malware, APT, supply-chain, cloud, ICS).
6. **Retention**: items older than 90 days are deleted (`EXCAT_NEWS_RETENTION_DAYS`).

## AI brief

With AI enabled, **AI brief** sends up to 60 recent headlines and excerpts, which are public data, to the
configured model. It returns a summary, themed clusters, and threat actors and campaigns. Every theme and
actor must reference real article IDs; anything that can't be traced to a source article is dropped.

## Managing feeds

Admins (`news:manage`) add, disable or remove feeds in **Settings → News feeds**. Feed URLs must be `https` and
resolve to a public address, and each feed may only be fetched from its own host. In AWS, add new feed hosts
to the Network Firewall allowlist.

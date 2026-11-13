---
id: news
title: Security News
page: /news
permission: news:view
summary: Recent attacks and security news from trusted sources, de-duplicated across outlets and linked to CVEs.
keywords: [news, rss, feeds, attacks, threat intel, cve, tags, brief]
docs: user-guide/news/
---

## What this page is for

A live feed of security news and advisories from trusted sources: CISA, BleepingComputer, The Hacker News,
SecurityWeek, Dark Reading, The Record, Krebs on Security, SANS ISC, and vendor threat-intel blogs (Unit 42,
Talos, Google/Mandiant, Microsoft, CrowdStrike). When several outlets report the same story, it appears once,
with "also covered by" links.

## How to use it

1. Filter by **keyword**, **source**, **tag** (ransomware, zero-day, APT, …), **CVE** or **date**.
2. Click a headline to read the full article at the source (new tab). Only headlines and short excerpts are
   shown here.
3. Click a **CVE chip** to open that CVE in CVE Intelligence. The CVE page also lists news that mentions it.
4. If AI is enabled, **AI brief (3 days)** summarizes recent stories into themes and lists the threat actors
   and campaigns named in them, each linked to its source articles.

## Fields and columns

| Field | Meaning |
|---|---|
| Also covered by | Other outlets reporting the same story (matched by URL or similar headline) |
| CVE chips | CVE IDs mentioned in the headline or excerpt |
| Tags | Topic tags detected from keywords |

## Required permissions

`news:view` to read. `news:manage` to add or remove feeds. `ai:use` for the AI brief.

## Common errors

- **"No stories yet"**: feeds refresh every 30 minutes. Check feed health under Settings → News feeds.

<!-- requires: news:manage -->
Admins manage feeds under **Settings → News feeds**, and set the refresh interval under **Settings → CVE
Sources → Security news feeds**.
<!-- /requires -->

## Learn more

See the [Security News guide](../user-guide/news.md).

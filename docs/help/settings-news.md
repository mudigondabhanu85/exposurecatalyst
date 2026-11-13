---
id: settings-news
title: Settings — News feeds
page: /settings/news
permission: news:manage
summary: Add, disable or remove RSS/Atom sources for the Security News tab and check their health.
keywords: [news, feeds, rss, atom, sources]
docs: user-guide/news/#managing-feeds
---

## What this page is for

Manages the RSS/Atom feeds behind the Security News tab.

## How to use it

1. Enter a **name** and the feed's **https URL**, choose a category, and click **Add feed**.
2. Untick **Enabled** to pause a feed, or **Remove** it to delete it with its stored items.
3. Check **Health** and **Last fetch**. Hover over the error for details.

## Fields and columns

| Column | Meaning |
|---|---|
| Items | Stored items, plus items added in the last run |
| (default) | One of the curated feeds shipped with ExposureCatalyst |

## Required permissions

`news:manage` (Admin, Super Admin).

## Common errors

- **"Feed URL rejected"**: feeds must be `https` and resolve to a public address. Internal and metadata
  addresses are blocked.
- **Failing with `HTTP 403`**: some sites block automated readers. Use the publisher's official feed URL.
- **`ParseError` / `EntitiesForbidden`**: the URL isn't a valid RSS/Atom feed, or it contains XML entities,
  which are refused for safety.

## Learn more

See [Managing feeds](../user-guide/news.md#managing-feeds).

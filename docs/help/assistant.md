---
id: assistant
title: Analyst assistant (AI)
page: /assistant
permission: ai:use
summary: Ask questions about CVEs and your exposure; answers come only from ExposureCatalyst data.
keywords: [ai, assistant, chat, ask]
docs: admin-guide/ai/#features
---

## What this page is for

A chat assistant scoped to ExposureCatalyst data: CVE records (scores, KEV, exploits, products) and your
exposure from integrations. It doesn't browse the web or act on your behalf.

## How to use it

1. Ask about a specific CVE ID, for example "What's our exposure to CVE-2024-21762 and what's the fix?", or
   use keywords.
2. Follow up in the same conversation. **Clear** starts over.
3. Treat answers as a starting point. Verify against the CVE page before acting.

## Required permissions

`ai:use` and `cve:view`.

## Common errors

- **"AI is not enabled"**: ask an administrator (Settings → AI Providers).
- **"Too many AI requests"**: the per-user limit is reached. Wait a minute.

## Learn more

See the [AI guide](../admin-guide/ai.md).

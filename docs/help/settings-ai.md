---
id: settings-ai
title: Settings — AI Providers
page: /settings/ai
permission: ai:manage
summary: Enable optional AI features, choose allowed providers and models, set redaction and budget, and track usage.
keywords: [ai, llm, openai, anthropic, claude, bedrock, azure, gemini, ollama, redaction, allowlist, budget, cost]
docs: admin-guide/ai/
---

## What this page is for

AI features are optional and **off by default**. This page controls whether they're on, which providers your
organization allows, which model serves each feature, how data is protected, and what it costs.

## How to use it

1. **Add provider**: pick the provider, then enter the endpoint (pre-filled), model, and credentials.
   Credentials are encrypted and never shown again. Optionally add prices per million tokens for cost
   tracking.
2. **Test**: sends a fixed "ping" prompt with no ExposureCatalyst data, and shows the reply.
3. **Policy**:
   - Tick **Enable AI features**.
   - Keep **redaction** on for external providers.
   - Optionally restrict the **provider allowlist** and set a **monthly budget**.
   - Route features to a primary provider and a fallback.
4. **Usage & cost** shows requests, tokens, cost, errors and how many requests were redacted, by provider
   and feature.

## Fields and columns

| Field | Meaning |
|---|---|
| Redact … external providers | Hostnames, IPs, owners, emails, cloud resource and account IDs are replaced with placeholders such as `[HOST_1]` before sending, and restored in the answer |
| Provider allowlist | Only ticked providers can be used. None ticked means all are allowed. Blocked providers are skipped even if routed |
| Routing | Primary and fallback provider per feature. *default* applies to features without their own route |
| Self-hosted | Ollama, vLLM, LM Studio or any OpenAI-compatible server you run. Private addresses need `EXCAT_AI_ALLOW_PRIVATE_ENDPOINTS=true` |

## Required permissions

`ai:manage` to configure (Admin, Super Admin). Users need `ai:use` to see AI features (Security Analyst,
Approver).

## Common errors

- **"Endpoint rejected"**: commercial providers accept only their official API host.
- **"blocked by allowlist"**: the allowlist excludes that provider. Tick it, or route a different provider.
- **"The monthly AI budget has been reached"**: raise the budget or wait for next month.

## Learn more

See the [AI guide](../admin-guide/ai.md) for the provider matrix and data-protection policy.

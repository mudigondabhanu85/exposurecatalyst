# Wiz

## Prerequisites

- A Wiz **service account**: Settings → Service Accounts → *Add*, type **Custom Integration (GraphQL API)**.
- Scopes: **`read:vulnerabilities`**, plus `read:resources` for asset details. No write scopes.
- Your tenant's **API endpoint URL** (User Settings → Tenant info), e.g. `https://api.us17.app.wiz.io/graphql`.

## Setup

1. Settings → Integrations → **Wiz → Set up**.
2. Base URL: the API endpoint URL (including `/graphql`). Client ID and secret: from the service account.
3. Token URL: `https://auth.app.wiz.io/oauth/token` (commercial) or `https://auth.app.wiz.us/oauth/token`
   (FedRAMP). Other hosts are refused.
4. Optional: *Finding statuses* (default `OPEN`).
5. **Save & test**, then enable.

## How it works

OAuth2 client credentials (`audience=wiz-api`) produce a bearer token, cached until shortly before it
expires. The GraphQL query `vulnerabilityFindings(filterBy: {vulnerabilityExternalId: [CVE], status: [...]})`
is paginated with `first: 500` and `endCursor`.

## Field mapping (defaults)

| Normalized | Wiz |
|---|---|
| hostname | `vulnerableAsset.name` |
| ip_address | `vulnerableAsset.ipAddresses.0` |
| os | `vulnerableAsset.operatingSystem` |
| cloud_account | `vulnerableAsset.subscriptionExternalId` |
| resource_id | `vulnerableAsset.providerUniqueId` (instance ID / ARN, used for cross-tool de-duplication) |
| detection_date | `firstDetectedAt` |
| source_ref | finding `id` |

## Rate limits

Wiz limits API calls per service account (about 3 requests/second). The connector is limited to 3 per
second, with backoff on `429`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `did not return an access token` | Wrong client ID/secret, or the token URL is for the wrong environment |
| `Wiz GraphQL error: … not authorized` | Add `read:vulnerabilities` to the service account |
| Schema errors after a Wiz release | Adjust the field mapping. Report if the query itself fails |

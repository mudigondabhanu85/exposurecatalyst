# Tanium

## Prerequisites

- **Tanium API Gateway** (Tanium Cloud, or on-prem Tanium Server 7.5+ with Gateway installed).
- An **API token** (Administration → API Tokens) for a user with **read-only** Gateway access and read access
  to the computer groups to be correlated.
- **Tanium Comply** vulnerability scanning, or a custom sensor that returns CVE IDs.
- Cloud base URL: `https://<customer>-api.cloud.tanium.com`. For on-prem, add your Tanium host to
  `EXCAT_EGRESS_ALLOWLIST` (and enable private networks if it resolves to an internal IP).

## Setup

1. Settings → Integrations → **Tanium → Set up**.
2. Base URL and API token. Tokens expire, so set a reminder to rotate.
3. *CVE sensor name*: default `Comply - Vulnerability Details`. Use your custom sensor if it differs.
   *Match operator*: `CONTAINS` (sensor value lists many CVEs) or `EQ`.
4. **Save & test**, then enable.

## How it works

GraphQL `POST /plugin/products/gateway/graphql` with the `session` header. The query asks for `endpoints`,
filtered where the configured sensor value matches the CVE ID, with cursor pagination (`first: 500`).

## Field mapping (defaults)

| Normalized | Tanium |
|---|---|
| hostname | `name` |
| ip_address | `ipAddress` |
| os | `os.name` |
| resource_id | `eid` |
| owner | `lastLoggedInUser` (override with a CMDB or custom sensor if preferred) |
| source_ref | endpoint `id` |

## Rate limits

The connector is limited to 10 requests/second, with backoff on `429` and `503`. Sensor-filtered queries can
be slow on large estates. Raise `EXCAT_CONNECTOR_TIMEOUT_SECONDS` if needed.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Token expired or revoked |
| `Tanium Gateway error: … sensor` | The sensor name doesn't exist. Check the exact name in Interact |
| 0 assets but Comply shows the CVE | Sensor results not yet collected (registered sensor or cache age). Re-check later |

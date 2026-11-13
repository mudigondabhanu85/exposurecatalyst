# ArmorCode

!!! warning "Confirm the API contract for your tenant"
    ArmorCode's API reference wasn't available to verify while this connector was built. Endpoint, CVE filter,
    results key, pagination and field mapping are therefore **settings** with documented defaults. Before
    enabling, check them against ArmorCode's API documentation for your tenant, then **Save & test** and run
    **Check now** on a CVE you know is present.

## Prerequisites

- A ArmorCode **API key/token** for a dedicated, **read-only** account with access to findings and assets.
- Your tenant's API base URL (default pattern: `https://app.armorcode.com`).

## Setup

1. Settings → Integrations → **ArmorCode → Set up**.
2. Base URL and API token. *Auth header* and *Auth value prefix* default to `Authorization: Bearer <token>`.
3. Review the endpoint settings:

    | Setting | Default | Meaning |
    |---|---|---|
    | Findings endpoint path | `/api/findings` | Endpoint returning findings |
    | CVE filter parameter | `cve` | Query (GET) or body (POST) parameter carrying the CVE ID |
    | HTTP method | `GET` | Use `POST` if the API takes a JSON filter body |
    | Results key | `content` | Dotted path to the list of findings in the response |
    | Pagination | `page (`totalPages`)` | `cursor` (next-cursor key), `page` (page number, stops at total pages or a short page) or `none` |
    | Page size | `500` | Sent as `limit` and `size` |
    | Connection test path | `/api/findings` | Cheap authenticated read for **Save & test** |

4. Adjust **Field mapping** to the record shape. Defaults: `asset.name`, `asset.ipAddress`, `asset.resourceId`, `owner`, `firstSeenDate`.
5. **Save & test**, then enable.

## Rate limits

The connector is limited to 10 requests/second, with retries and backoff on `429`/`5xx`. Pagination stops
after 1,000 pages, and results are capped at `EXCAT_CONNECTOR_MAX_ASSETS`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401/403` | Token invalid or missing read scope |
| `HTTP 404` | Findings path differs for your API version |
| `results key … is not a list` | Point *Results key* at the array of findings |
| `returned non-JSON` | Wrong path (an HTML login page), or the API needs a different auth header |
| Assets found but hostnames empty | Fix the field mapping paths |

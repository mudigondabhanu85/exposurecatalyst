# ServiceNow CMDB

The ServiceNow connector does two things:

1. **Affected assets.** If you license **Vulnerability Response**, it reads vulnerable items for the CVE and
   their configuration items.
2. **Enrichment.** For every asset found by *other* tools, it looks the host up in the CMDB (by name or IP) and
   fills in **owner**, **business unit** and **environment** when the tool didn't provide them. This is
   capped at 200 lookups per check.

## Prerequisites

- A dedicated **integration user** with *Web service access only*.
- Roles: **`cmdb_read`**, plus **`sn_vul.read_only`** if Vulnerability Response is used. Confirm ACLs allow
  Table API reads on `cmdb_ci_computer` and `sn_vul_vulnerable_item`.
- Instance URL: `https://<instance>.service-now.com`.

## Setup

1. Settings → Integrations → **ServiceNow → Set up**.
2. Base URL, integration user and password.
3. *Vulnerable item table*: `sn_vul_vulnerable_item`. **Leave it empty** if you don't license Vulnerability
   Response. CVE lookups then report *unsupported* (the matrix row stays *Not Integrated*), and the connector
   is used for enrichment only.
4. *CI table for enrichment*: `cmdb_ci_computer`, or `cmdb_ci_server` if you only track servers.
5. **Save & test**, then enable.

## How it works

- `GET /api/now/table/sn_vul_vulnerable_item?sysparm_query=vulnerability.id=<CVE>^active=true` with
  dot-walked `cmdb_ci.*` fields, `sysparm_display_value=true`, and `sysparm_offset`/`sysparm_limit=1000`
  pagination.
- Enrichment: `GET /api/now/table/cmdb_ci_computer?sysparm_query=name=<host>^ORname=<fqdn>^ORip_address=<ip>&sysparm_limit=1`.
  Values interpolated into encoded queries are stripped of `^` and newlines to prevent query injection.

## Field mapping (defaults)

| Normalized | ServiceNow |
|---|---|
| hostname / ip_address / os | `cmdb_ci.name` / `cmdb_ci.ip_address` / `cmdb_ci.os` |
| resource_id | `cmdb_ci.object_id` (cloud instance ID for discovered cloud CIs) |
| owner | `cmdb_ci.owned_by` |
| business_unit | `cmdb_ci.department` (many organizations use a custom field; override it) |
| environment | `cmdb_ci.used_for` (Production / Development / …) |
| detection_date | `first_found` |
| source_ref | vulnerable item `number` |

## Rate limits

ServiceNow applies instance-level REST rate-limit rules. The connector is limited to 20 requests/second and
honours `429` with `Retry-After`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `HTTP 401` | Wrong credentials, or the user isn't allowed web-service access |
| `HTTP 403` | An ACL blocks the table. Grant read on the table and fields listed above |
| Row shows *unsupported* | Expected without Vulnerability Response. Enrichment still works |
| Owner/BU empty after enrichment | The host name in the source tool doesn't match the CI name. Map a different CI table or field |

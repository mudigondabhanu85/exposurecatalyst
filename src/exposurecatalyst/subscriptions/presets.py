"""Pre-built subscription presets. Each is a template for the generic engine (engine.py): auth, endpoints, pagination
and a JSONPath field mapping — every value is editable per subscription, so a tenant whose API differs can be
adapted without code changes.

``api_status``: "documented" = follows the vendor's public API reference; "confirm" = the reference is
tenant-gated or the vendor offers several APIs: confirm the defaults with **Test & preview** before enabling.
Vendors whose REST APIs require request signing (Cyware CTIX, Silobreaker) are offered through their TAXII 2.1 /
authenticated RSS feeds, which the engine supports natively.
"""

from __future__ import annotations

from typing import Any

SINCE = "{since_iso}"

PRESETS: dict[str, dict[str, Any]] = {
    "recorded_future": {
        "vendor": "Recorded Future",
        "source_type": "rest",
        "api_status": "documented",
        "base_url": "https://api.recordedfuture.com",
        "hosts": ["api.recordedfuture.com"],
        "auth": {"type": "api_key_header", "header": "X-RFToken"},
        "secrets": ["api_key"],
        "endpoints": [
            {
                "name": "Vulnerabilities (risk ≥ 65)",
                "target": "cve",
                "method": "GET",
                "path": "/v2/vulnerability/search",
                "params": {
                    "riskScore": "[65,100]",
                    "lastSeen": "[{since_iso},]",
                    "fields": "entity,risk,timestamps,intelCard",
                    "limit": "{limit}",
                },
                "results_path": "$.data.results[*]",
                "pagination": {"type": "offset", "param": "from", "size": 100},
                "mapping": {
                    "external_id": "$.entity.id",
                    "cve_id": "$.entity.name",
                    "title": "$.entity.name",
                    "summary": "$.risk.criticalityLabel",
                    "severity": "$.risk.score",
                    "published": "$.timestamps.lastSeen",
                    "url": "$.intelCard",
                },
            }
        ],
        "docs": "Connect API v2 token (Settings → API access). Risk score ≥ 65 = High/Critical.",
    },
    "google_ti_mandiant": {
        "vendor": "Google Threat Intelligence / Mandiant",
        "source_type": "rest",
        "api_status": "documented",
        "base_url": "https://api.intelligence.mandiant.com",
        "hosts": ["api.intelligence.mandiant.com"],
        "auth": {
            "type": "oauth2_cc",
            "token_url": "https://api.intelligence.mandiant.com/token",  # nosec B105 - token endpoint URL, not a credential
            "client_auth": "basic",
        },
        "headers": {"X-App-Name": "ExposureCatalyst"},
        "secrets": ["client_id", "client_secret"],
        "endpoints": [
            {
                "name": "Vulnerabilities",
                "target": "cve",
                "method": "GET",
                "path": "/v4/vulnerability",
                "params": {"start_epoch": "{since_epoch}", "limit": "{limit}"},
                "results_path": "$.vulnerability[*]",
                "pagination": {"type": "cursor", "param": "next", "next_path": "$.next"},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.cve_id",
                    "title": "$.title",
                    "summary": "$.analysis",
                    "description": "$.description",
                    "severity": "$.risk_rating",
                    "exploited": "$.exploitation_state",
                    "published": "$.publish_date",
                    "references": "$.sources[*].url",
                },
            }
        ],
        "docs": "Mandiant Threat Intelligence API v4 key ID + secret (Settings → API Access & Keys).",
    },
    "vulncheck": {
        "vendor": "VulnCheck",
        "source_type": "rest",
        "api_status": "documented",
        "base_url": "https://api.vulncheck.com",
        "hosts": ["api.vulncheck.com"],
        "auth": {"type": "bearer"},
        "secrets": ["token"],
        "endpoints": [
            {
                "name": "VulnCheck KEV",
                "target": "cve",
                "method": "GET",
                "path": "/v3/index/vulncheck-kev",
                "params": {"limit": "{limit}", "start_cursor": "true"},
                "results_path": "$.data[*]",
                "pagination": {
                    "type": "cursor",
                    "param": "cursor",
                    "next_path": "$._meta.next_cursor",
                    "drop_params": ["start_cursor"],
                },
                "mapping": {
                    "external_id": "$.cve[0]",
                    "cve_id": "$.cve",
                    "title": "$.vulnerabilityName",
                    "description": "$.shortDescription",
                    "exploited": "=true",
                    "published": "$.date_added",
                    "references": "$.vulncheck_xdb[*].clone_ssh_url",
                    "tags": "$.vendorProject",
                },
            }
        ],
        "docs": "VulnCheck API token (paid tiers include the full KEV and exploit intelligence indices).",
    },
    "flashpoint": {
        "vendor": "Flashpoint (VulnDB)",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://api.flashpoint.io",
        "hosts": ["api.flashpoint.io", "vulndb.flashpoint.io"],
        "auth": {"type": "bearer"},
        "secrets": ["token"],
        "endpoints": [
            {
                "name": "Vulnerability intelligence",
                "target": "cve",
                "method": "GET",
                "path": "/vulnerability-intelligence/v1/vulnerabilities",
                "params": {"updated_after": "{since_iso}", "size": "{limit}"},
                "results_path": "$.results[*]",
                "pagination": {"type": "page", "param": "page"},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.cve_ids",
                    "title": "$.title",
                    "description": "$.description",
                    "severity": "$.cvss_v3_score",
                    "exploited": "$.exploit_status",
                    "published": "$.disclosed_at",
                    "references": "$.references[*].url",
                },
            }
        ],
        "docs": "Flashpoint Ignite API token with Vulnerability Intelligence (VulnDB) entitlement.",
    },
    "intel471": {
        "vendor": "Intel 471",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://api.intel471.com",
        "hosts": ["api.intel471.com"],
        "auth": {"type": "basic"},
        "secrets": ["username", "password"],
        "endpoints": [
            {
                "name": "CVE reports",
                "target": "cve",
                "method": "GET",
                "path": "/v1/cve/reports",
                "params": {"from": "{since_epoch_ms}", "count": "{limit}"},
                "results_path": "$.cveReports[*]",
                "pagination": {"type": "offset", "param": "offset", "size": 100},
                "mapping": {
                    "external_id": "$.uid",
                    "cve_id": "$.data.cve_report.name",
                    "title": "$.data.cve_report.name",
                    "summary": "$.data.cve_report.summary",
                    "severity": "$.data.cve_report.risk_level",
                    "exploited": "$.data.cve_report.exploit_status.wild",
                    "published": "$.activity.last",
                },
            }
        ],
        "docs": "Titan API: account email as username, API key as password.",
    },
    "crowdstrike_intel": {
        "vendor": "CrowdStrike Falcon Intelligence",
        "source_type": "rest",
        "api_status": "documented",
        "base_url": "https://api.crowdstrike.com",
        "hosts": [
            "api.crowdstrike.com",
            "api.us-2.crowdstrike.com",
            "api.eu-1.crowdstrike.com",
            "api.laggar.gcw.crowdstrike.com",
        ],
        "auth": {"type": "oauth2_cc", "token_url": "{base_url}/oauth2/token", "client_auth": "body"},  # nosec B105 - token endpoint URL, not a credential
        "secrets": ["client_id", "client_secret"],
        "endpoints": [
            {
                "name": "Intelligence reports",
                "target": "news",
                "method": "GET",
                "path": "/intel/combined/reports/v1",
                "params": {"filter": "created_date:>{since_epoch}", "sort": "created_date|desc", "limit": "{limit}"},
                "results_path": "$.resources[*]",
                "pagination": {"type": "offset", "param": "offset", "size": 100},
                "mapping": {
                    "external_id": "$.id",
                    "title": "$.name",
                    "summary": "$.short_description",
                    "url": "$.url",
                    "published": "$.created_date",
                    "tags": "$.tags[*].value",
                },
            },
            {
                "name": "Vulnerabilities",
                "target": "cve",
                "method": "GET",
                "path": "/intel/combined/vulnerabilities/v1",
                "params": {"filter": "updated_timestamp:>{since_epoch}", "limit": "{limit}"},
                "results_path": "$.resources[*]",
                "pagination": {"type": "offset", "param": "offset", "size": 100},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.id",
                    "title": "$.id",
                    "description": "$.description",
                    "severity": "$.severity",
                    "exploited": "$.exploit_status",
                    "published": "$.updated_timestamp",
                },
            },
        ],
        "docs": "API client with Reports (Falcon Intelligence): Read and Vulnerabilities (Falcon Intelligence): Read.",
    },
    "msft_defender_ti": {
        "vendor": "Microsoft Defender Threat Intelligence",
        "source_type": "rest",
        "api_status": "documented",
        "base_url": "https://graph.microsoft.com",
        "hosts": ["graph.microsoft.com"],
        "auth": {
            "type": "oauth2_cc",
            "token_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",  # nosec B105 - token endpoint URL, not a credential
            "scope": "https://graph.microsoft.com/.default",
            "client_auth": "body",
        },
        "secrets": ["client_id", "client_secret"],
        "fields": ["tenant_id"],
        "endpoints": [
            {
                "name": "Threat intelligence articles",
                "target": "news",
                "method": "GET",
                "path": "/v1.0/security/threatIntelligence/articles",
                "params": {"$filter": "createdDateTime ge {since_iso}", "$top": "{limit}"},
                "results_path": "$.value[*]",
                "pagination": {"type": "next_url", "next_path": "$['@odata.nextLink']"},
                "mapping": {
                    "external_id": "$.id",
                    "title": "$.title",
                    "summary": "$.summary.content",
                    "published": "$.createdDateTime",
                    "tags": "$.tags",
                },
            }
        ],
        "token_hosts": ["login.microsoftonline.com"],
        "docs": "Entra ID app with Microsoft Graph application permission ThreatIntelligence.Read.All "
        "(Defender TI licence). Microsoft is folding the standalone Defender TI portal into Defender XDR; "
        "the Graph threatIntelligence API remains the integration point.",
    },
    "cyware": {
        "vendor": "Cyware (CTIX TAXII)",
        "source_type": "taxii",
        "api_status": "confirm",
        "base_url": "https://example.cyware.com/ctixapi/ctix21/",
        "hosts": ["*.cyware.com"],
        "auth": {"type": "basic"},
        "secrets": ["username", "password"],
        "fields": ["collection_id"],
        "docs": "CTIX TAXII 2.1 server: API root, collection ID and TAXII credentials (Administration → "
        "Integrations → TAXII). CTIX's REST API uses request signing; TAXII avoids storing the signing key.",
    },
    "threatconnect": {
        "vendor": "ThreatConnect",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://app.threatconnect.com",
        "hosts": ["*.threatconnect.com"],
        "auth": {"type": "api_key_header", "header": "Authorization", "prefix": "TC-Token "},
        "secrets": ["api_key"],
        "endpoints": [
            {
                "name": "Vulnerability groups",
                "target": "cve",
                "method": "GET",
                "path": "/api/v3/groups",
                "params": {
                    "tql": 'typeName EQ "Vulnerability" AND dateAdded > "{since_iso}"',
                    "resultLimit": "{limit}",
                },
                "results_path": "$.data[*]",
                "pagination": {"type": "next_url", "next_path": "$.next"},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.name",
                    "title": "$.name",
                    "description": "$.description",
                    "published": "$.dateAdded",
                    "url": "$.webLink",
                },
            }
        ],
        "docs": "API user token (TC-Token). For HMAC (access ID + secret) API users, use the custom REST source with a "
        "proxy that signs requests, or the platform's TAXII server.",
    },
    "anomali": {
        "vendor": "Anomali ThreatStream",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://api.threatstream.com",
        "hosts": ["api.threatstream.com", "*.threatstream.com"],
        "auth": {"type": "api_key_header", "header": "Authorization", "prefix": "apikey "},
        "secrets": ["api_key"],
        "endpoints": [
            {
                "name": "Vulnerabilities",
                "target": "cve",
                "method": "GET",
                "path": "/api/v1/vulnerability/",
                "params": {"modified_ts__gte": "{since_iso}", "limit": "{limit}"},
                "results_path": "$.objects[*]",
                "pagination": {"type": "next_url", "next_path": "$.meta.next"},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.name",
                    "title": "$.name",
                    "description": "$.description",
                    "published": "$.created_ts",
                    "tags": "$.tags[*].name",
                },
            }
        ],
        "docs": "API key as `<username>:<api key>` (Settings → My Profile → API key).",
    },
    "feedly": {
        "vendor": "Feedly for Threat Intelligence",
        "source_type": "rest",
        "api_status": "documented",
        "base_url": "https://api.feedly.com",
        "hosts": ["api.feedly.com"],
        "auth": {"type": "bearer"},
        "secrets": ["token"],
        "fields": ["stream_id"],
        "endpoints": [
            {
                "name": "Board / feed stream",
                "target": "news",
                "method": "GET",
                "path": "/v3/streams/contents",
                "params": {"streamId": "{stream_id}", "count": "{limit}", "newerThan": "{since_epoch_ms}"},
                "results_path": "$.items[*]",
                "pagination": {"type": "cursor", "param": "continuation", "next_path": "$.continuation"},
                "mapping": {
                    "external_id": "$.id",
                    "title": "$.title",
                    "summary": "$.summary.content",
                    "url": "$.alternate[0].href",
                    "published": "$.published",
                    "tags": "$.commonTopics[*].label",
                    "cve_id": "$.entities[*].label",
                },
            }
        ],
        "docs": "Feedly API token (Enterprise / Threat Intelligence). Stream ID of a board or AI Feed.",
    },
    "silobreaker": {
        "vendor": "Silobreaker (authenticated RSS)",
        "source_type": "rss",
        "api_status": "confirm",
        "base_url": "https://my.silobreaker.com/rss/",
        "hosts": ["*.silobreaker.com"],
        "auth": {"type": "none"},
        "secrets": [],
        "docs": "Silobreaker RSS export URL for a saved search (the URL embeds an access key: it is stored as the "
        "base URL, which is admin-only). Silobreaker's REST API uses HMAC request signing.",
    },
    "dataminr": {
        "vendor": "Dataminr",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://gateway.dataminr.com",
        "hosts": ["gateway.dataminr.com"],
        "auth": {
            "type": "oauth2_cc",
            "token_url": "https://gateway.dataminr.com/auth/2/token",  # nosec B105 - token endpoint URL, not a credential
            "grant_type": "api_key",
            "client_auth": "body",
        },
        "secrets": ["client_id", "client_secret"],
        "fields": ["list_ids"],
        "endpoints": [
            {
                "name": "Alerts",
                "target": "news",
                "method": "GET",
                "path": "/api/3/alerts",
                "params": {"lists": "{list_ids}", "num": "{limit}"},
                "results_path": "$.data.alerts[*]",
                "pagination": {"type": "cursor", "param": "from", "next_path": "$.data.to"},
                "mapping": {
                    "external_id": "$.alertId",
                    "title": "$.headline",
                    "summary": "$.caption",
                    "url": "$.expandAlertURL",
                    "published": "$.eventTime",
                    "tags": "$.categories[*].name",
                },
            }
        ],
        "docs": "Dataminr Pulse for Cyber Risk API client; list IDs (comma-separated) from your Dataminr lists.",
    },
    "socradar": {
        "vendor": "SOCRadar",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://platform.socradar.com",
        "hosts": ["platform.socradar.com"],
        "auth": {"type": "api_key_query", "param": "key"},
        "secrets": ["api_key"],
        "fields": ["company_id"],
        "endpoints": [
            {
                "name": "Incidents",
                "target": "news",
                "method": "GET",
                "path": "/api/company/{company_id}/incidents/v4",
                "params": {"start_date": "{since_date}", "limit": "{limit}"},
                "results_path": "$.data[*]",
                "pagination": {"type": "page", "param": "page"},
                "mapping": {
                    "external_id": "$.alarm_id",
                    "title": "$.alarm_type_details.alarm_main_type",
                    "summary": "$.content",
                    "published": "$.date",
                    "tags": "$.tags",
                },
            }
        ],
        "docs": "SOCRadar company API key and company ID (Settings → API Options).",
    },
    "cybersixgill": {
        "vendor": "Cybersixgill",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://api.cybersixgill.com",
        "hosts": ["api.cybersixgill.com"],
        "auth": {"type": "oauth2_cc", "token_url": "https://api.cybersixgill.com/auth/token", "client_auth": "body"},  # nosec B105 - token endpoint URL, not a credential
        "secrets": ["client_id", "client_secret"],
        "endpoints": [
            {
                "name": "DVE feed",
                "target": "cve",
                "method": "GET",
                "path": "/dve_enrich/feed",
                "params": {"from_date": "{since_iso}", "size": "{limit}"},
                "results_path": "$.objects[*]",
                "pagination": {"type": "offset", "param": "from", "size": 100},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.name",
                    "title": "$.name",
                    "description": "$.description",
                    "severity": "$.x_sixgill_info.score.current",
                    "published": "$.modified",
                },
            }
        ],
        "docs": "Cybersixgill API client (DVE / vulnerability intelligence entitlement).",
    },
    "reliaquest_greymatter": {
        "vendor": "ReliaQuest GreyMatter Digital Risk",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://api.searchlight.app",
        "hosts": ["api.searchlight.app", "*.searchlight.app"],
        "auth": {"type": "basic"},
        "secrets": ["username", "password"],
        "fields": ["account_id"],
        "headers": {"searchlight-account-id": "{account_id}"},
        "endpoints": [
            {
                "name": "Triage item events",
                "target": "news",
                "method": "GET",
                "path": "/v1/triage-item-events",
                "params": {"limit": "{limit}"},
                "results_path": "$[*]",
                "pagination": {"type": "cursor", "param": "event-num-after", "next_path": "$[-1].event-num"},
                "mapping": {
                    "external_id": "$.event-num",
                    "title": "$.event-action",
                    "summary": "$.triage-item-id",
                    "published": "$.event-created",
                },
            }
        ],
        "docs": "GreyMatter Digital Risk (SearchLight) API key and secret plus your account ID.",
    },
    "securin": {
        "vendor": "Securin",
        "source_type": "rest",
        "api_status": "confirm",
        "base_url": "https://api.securin.io",
        "hosts": ["*.securin.io"],
        "auth": {"type": "api_key_header", "header": "x-api-key"},
        "secrets": ["api_key"],
        "endpoints": [
            {
                "name": "Vulnerability intelligence",
                "target": "cve",
                "method": "GET",
                "path": "/v1/vulnerabilities",
                "params": {"updated_since": "{since_iso}", "limit": "{limit}"},
                "results_path": "$.data[*]",
                "pagination": {"type": "page", "param": "page"},
                "mapping": {
                    "external_id": "$.id",
                    "cve_id": "$.cve_id",
                    "title": "$.title",
                    "description": "$.description",
                    "severity": "$.vrs_score",
                    "exploited": "$.is_exploited",
                    "published": "$.updated_at",
                },
            }
        ],
        "docs": "Securin Vulnerability Intelligence API key.",
    },
    # ---- custom sources (no vendor defaults) ----------------------------------------------------------------
    "custom_rest": {
        "vendor": "Custom",
        "source_type": "rest",
        "api_status": "custom",
        "base_url": "",
        "hosts": [],
        "auth": {"type": "none"},
        "secrets": [],
        "endpoints": [],
        "docs": "Any REST/JSON API.",
    },
    "custom_rss": {
        "vendor": "Custom",
        "source_type": "rss",
        "api_status": "custom",
        "base_url": "",
        "hosts": [],
        "auth": {"type": "none"},
        "secrets": [],
        "docs": "Authenticated RSS / Atom feed.",
    },
    "custom_taxii": {
        "vendor": "Custom",
        "source_type": "taxii",
        "api_status": "custom",
        "base_url": "",
        "hosts": [],
        "auth": {"type": "basic"},
        "secrets": [],
        "fields": ["collection_id"],
        "docs": "TAXII 2.1 API root + collection (STIX 2.1 vulnerability / report objects).",
    },
    "manual": {
        "vendor": "Manual",
        "source_type": "manual",
        "api_status": "custom",
        "base_url": None,
        "hosts": [],
        "auth": {"type": "none"},
        "secrets": [],
        "docs": "Portal / PDF / email subscriptions: manual entry and file import only.",
    },
}

AUTH_TYPES = ("none", "api_key_header", "api_key_query", "bearer", "basic", "oauth2_cc", "custom_headers")
SECRET_KEYS = {"api_key", "token", "username", "password", "client_id", "client_secret", "custom_headers"}


def catalog() -> list[dict[str, Any]]:
    return [
        {
            "key": k,
            **{
                f: v.get(f)
                for f in (
                    "vendor",
                    "source_type",
                    "api_status",
                    "base_url",
                    "auth",
                    "secrets",
                    "fields",
                    "headers",
                    "endpoints",
                    "docs",
                )
            },
        }
        for k, v in PRESETS.items()
    ]

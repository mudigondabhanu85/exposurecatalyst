"""Application settings.

Every setting is read from an ``EXCAT_``-prefixed environment variable (or ``.env``).
Field descriptions are the source for ``docs/reference/configuration.md`` — keep them accurate.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EXCAT_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- General -----------------------------------------------------------------------------
    env: Literal["dev", "test", "prod"] = Field(
        "prod", description="Runtime environment. `prod` enforces strict security checks at startup."
    )
    public_url: str = Field(
        "http://localhost:8000",
        description="External base URL users reach the app on. Used for Origin/CSRF checks and links.",
    )
    log_level: str = Field("INFO", description="Log level: DEBUG, INFO, WARNING, ERROR.")
    log_json: bool = Field(True, description="Emit structured JSON logs (recommended outside local dev).")
    api_docs_enabled: bool = Field(True, description="Serve Swagger UI at /api/docs and ReDoc at /api/redoc.")
    metrics_enabled: bool = Field(
        True, description="Expose Prometheus metrics at /metrics (block this path at the load balancer)."
    )
    cors_origins: str = Field(
        "", description="Comma-separated extra origins allowed for CORS and state-changing requests."
    )

    # --- Database ----------------------------------------------------------------------------
    database_url: SecretStr = Field(
        SecretStr("sqlite:///./exposurecatalyst.db"),
        description="SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host:5432/excat?sslmode=require`. "
        "SQLite is for development only.",
    )
    db_pool_size: int = Field(10, ge=1, description="Connection pool size (non-SQLite).")
    db_max_overflow: int = Field(20, ge=0, description="Extra connections allowed above the pool size.")
    db_pool_recycle_seconds: int = Field(1800, ge=60, description="Recycle connections after N seconds.")
    db_echo: bool = Field(False, description="Log every SQL statement (debug only — never in prod).")

    # --- Security ----------------------------------------------------------------------------
    encryption_key: SecretStr | None = Field(
        None,
        description="Fernet key used to encrypt secrets at rest (TOTP seeds, connector credentials). "
        "Generate with `exposurecatalyst gen-key`. Required in prod.",
    )
    session_idle_timeout_minutes: int = Field(30, ge=5, description="Sign out after N minutes of inactivity.")
    session_absolute_timeout_minutes: int = Field(
        480, ge=15, description="Maximum session lifetime regardless of activity."
    )
    cookie_secure: bool = Field(True, description="Mark session cookies Secure (HTTPS only). Must be true in prod.")
    login_max_attempts: int = Field(5, ge=3, description="Failed logins before the account is locked.")
    login_lockout_minutes: int = Field(15, ge=1, description="Account lockout duration.")
    login_rate_limit_per_minute: int = Field(10, ge=1, description="Login attempts allowed per client IP per minute.")
    password_min_length: int = Field(12, ge=8, description="Minimum password length for local accounts.")
    require_mfa_for_local_admins: bool = Field(
        True, description="Local accounts holding admin permissions must enrol TOTP before using admin APIs."
    )

    # --- CVE sources -------------------------------------------------------------------------
    nvd_base_url: str = Field("https://services.nvd.nist.gov/rest/json/cves/2.0", description="NVD CVE API 2.0 endpoint.")
    nvd_api_key: SecretStr | None = Field(
        None, description="NVD API key (raises the rate limit from 5 to 50 requests / 30 s)."
    )
    kev_url: str = Field(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="CISA Known Exploited Vulnerabilities JSON feed.",
    )
    epss_api_url: str = Field("https://api.first.org/data/v1/epss", description="FIRST EPSS API endpoint.")
    epss_bulk_url: str = Field(
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        description="Daily EPSS bulk CSV (used when many CVEs need scores).",
    )
    epss_bulk_threshold: int = Field(
        2000, ge=100, description="Switch from per-CVE API lookups to the bulk CSV above this many CVEs."
    )
    fetch_interval_minutes: int = Field(
        60, ge=5, description="Default refresh interval for every source (override per source in Settings)."
    )
    initial_backfill_days: int = Field(7, ge=1, le=120, description="Days of NVD history fetched on first run.")
    cvss_preferred_versions: str = Field(
        "3.1,4.0,3.0,2.0", description="Order of CVSS versions used for the headline score and severity."
    )
    scheduler_embedded: bool = Field(
        False, description="Run the ingestion scheduler inside the API process (single-node / dev only)."
    )
    scheduler_tick_seconds: int = Field(60, ge=10, description="How often the scheduler checks for due sources.")
    job_stale_after_minutes: int = Field(
        120, ge=10, description="A source stuck in `running` longer than this is considered crashed and re-claimable."
    )

    # --- Outbound HTTP / SSRF ----------------------------------------------------------------
    http_timeout_seconds: float = Field(30.0, gt=0, description="Timeout for outbound HTTP requests.")
    http_max_retries: int = Field(5, ge=0, le=10, description="Retries for 429/5xx/transport errors.")
    http_backoff_base_seconds: float = Field(2.0, gt=0, description="Exponential backoff base delay.")
    http_backoff_max_seconds: float = Field(120.0, gt=0, description="Maximum backoff delay.")
    http_user_agent: str = Field("ExposureCatalyst/0.1", description="User-Agent sent to upstream sources.")
    egress_allowlist: str = Field(
        "services.nvd.nist.gov,www.cisa.gov,api.first.org,epss.empiricalsecurity.com",
        description="Comma-separated hostnames the app may call. `*.example.com` matches subdomains.",
    )
    ssrf_allow_private_networks: bool = Field(
        False,
        description="Allow outbound calls to private/loopback/link-local/metadata addresses. Keep false "
        "unless an on-prem integration requires it.",
    )
    ssrf_resolve_dns: bool = Field(True, description="Resolve hostnames and block private results (DNS rebinding guard).")

    # --- Advisories & email ---------------------------------------------------------------
    advisory_sources: str = Field(
        "Qualys,Tanium,Wiz,Zafran,ArmorCode,ServiceNow CMDB",
        description="Rows shown in every advisory's asset validation matrix (comma-separated, in order).",
    )
    upload_max_bytes: int = Field(5_242_880, ge=10_240, description="Maximum size of a CSV/XLSX asset upload (bytes).")
    upload_max_rows: int = Field(10_000, ge=10, description="Maximum rows imported from one asset upload.")
    smtp_allowed_ports: str = Field("25,465,587,2525", description="Ports an admin may configure for the SMTP relay.")
    smtp_allow_private_hosts: bool = Field(
        False,
        description="Allow an SMTP relay on a private/internal address (common for corporate relays). Cloud "
        "metadata addresses are always blocked.",
    )
    smtp_allow_plaintext: bool = Field(
        False, description="Allow SMTP without TLS. Development only (e.g. a local Mailpit); never in prod."
    )
    smtp_timeout_seconds: float = Field(30.0, gt=0, description="SMTP connect/send timeout.")

    # --- Integrations ---------------------------------------------------------------------
    connector_max_assets: int = Field(
        10_000, ge=100, description="Maximum affected assets fetched from one integration for one CVE (result is flagged truncated)."
    )
    connector_timeout_seconds: float = Field(60.0, gt=0, description="HTTP timeout for connector API calls.")
    connector_cache_minutes: int = Field(
        60, ge=0, description="Re-use an integration's CVE results younger than this instead of calling the tool again."
    )

    # --- Paths -------------------------------------------------------------------------------
    frontend_dist_dir: Path = Field(PROJECT_ROOT / "frontend" / "dist", description="Built React app served at /.")
    docs_site_dir: Path = Field(PROJECT_ROOT / "dist" / "docs" / "site", description="Built MkDocs site served at /docs.")
    help_dir: Path = Field(PROJECT_ROOT / "docs" / "help", description="In-app help Markdown (single source with docs).")
    brand_dir: Path = Field(PROJECT_ROOT / "brand", description="Brand kit (logos, tokens) used in emails, exports and docs.")
    changelog_path: Path = Field(PROJECT_ROOT / "CHANGELOG.md", description="Changelog shown in Help Center → What's new.")

    # ---------------------------------------------------------------------------------------
    @property
    def cors_origin_list(self) -> list[str]:
        return _csv(self.cors_origins)

    @property
    def allowed_origins(self) -> set[str]:
        parts = urlsplit(self.public_url)
        return {f"{parts.scheme}://{parts.netloc}", *self.cors_origin_list}

    @property
    def egress_allowlist_list(self) -> list[str]:
        return [h.lower() for h in _csv(self.egress_allowlist)]

    @property
    def advisory_source_list(self) -> list[str]:
        return _csv(self.advisory_sources)

    @property
    def smtp_port_list(self) -> list[int]:
        return [int(p) for p in _csv(self.smtp_allowed_ports)]

    @property
    def cvss_version_order(self) -> list[str]:
        return _csv(self.cvss_preferred_versions)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.get_secret_value().startswith("sqlite")

    @model_validator(mode="after")
    def _prod_guardrails(self) -> Settings:
        if self.env == "prod":
            problems = []
            if self.encryption_key is None:
                problems.append("EXCAT_ENCRYPTION_KEY is required")
            if not self.cookie_secure:
                problems.append("EXCAT_COOKIE_SECURE must be true")
            if self.is_sqlite:
                problems.append("SQLite is not supported in prod; set EXCAT_DATABASE_URL")
            if self.smtp_allow_plaintext:
                problems.append("EXCAT_SMTP_ALLOW_PLAINTEXT must be false")
            if self.db_echo:
                problems.append("EXCAT_DB_ECHO must be false")
            if problems:
                raise ValueError("Unsafe production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

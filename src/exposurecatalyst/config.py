"""Application settings.

Every setting is read from an ``EXCAT_``-prefixed environment variable (or ``.env``). Any setting can
instead be read from a file named by ``EXCAT_<NAME>_FILE`` (Docker secrets / the bootstrap's secrets
volume); an explicitly set, non-empty ``EXCAT_<NAME>`` always wins over the file.

Optionally, a YAML file named by ``EXCAT_CONFIG_FILE`` (Docker: ``config/exposurecatalyst.yaml``) supplies values
too. Precedence:
non-empty environment variable > ``.env`` > ``*_FILE`` > YAML > default. Without a YAML file nothing changes.
Field descriptions are the source for ``docs/reference/configuration.md`` — keep them accurate.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


class FileSecretsSource(PydanticBaseSettingsSource):
    """``EXCAT_<NAME>_FILE=/path`` → value of setting ``<name>`` (trailing newline stripped).

    Used only when ``EXCAT_<NAME>`` is unset or empty in both the environment and ``.env``, so existing
    deployments that set values directly behave exactly as before.
    """

    def __init__(self, settings_cls: type[BaseSettings], dotenv: dict[str, Any]):
        super().__init__(settings_cls)
        self._dotenv = {k.lower(): v for k, v in dotenv.items()}

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:  # pragma: no cover
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in self.settings_cls.model_fields:
            env = f"EXCAT_{name.upper()}"
            explicit = os.environ.get(env) or self._dotenv.get(name) or self._dotenv.get(env.lower())
            path = os.environ.get(f"{env}_FILE")
            if explicit or not path:
                continue
            try:
                out[name] = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
            except OSError as exc:
                raise ValueError(f"{env}_FILE: cannot read {path}: {exc.strerror}") from exc
        return out


def config_file_path() -> Path | None:
    """The YAML config file named by EXCAT_CONFIG_FILE (docker compose and run.sh set it). Opt-in on purpose:
    a config file sitting in a checkout must not silently change local runs or the test suite."""
    explicit = os.environ.get("EXCAT_CONFIG_FILE", "").strip()
    return Path(explicit) if explicit else None


def load_config_file(path: Path | None = None) -> dict[str, Any]:
    """Parse the YAML config file (safe_load). Missing file → {}. Keys are setting names without EXCAT_."""
    path = path or config_file_path()
    if path is None or not path.is_file():
        return {}
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return {str(k).lower(): v for k, v in data.items() if v is not None}


class YamlConfigSource(PydanticBaseSettingsSource):
    """Values from the YAML config file, used only where neither the environment nor .env sets a non-empty
    value (compose passes unset variables as empty strings). Nested ``features`` keys are merged per key."""

    def __init__(self, settings_cls: type[BaseSettings], dotenv: dict[str, Any]):
        super().__init__(settings_cls)
        self._dotenv = {k.lower(): v for k, v in dotenv.items()}

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:  # pragma: no cover
        return None, field_name, False

    def _explicit(self, env_name: str) -> bool:
        return bool(os.environ.get(env_name) or self._dotenv.get(env_name.lower())
                    or self._dotenv.get(env_name.lower().removeprefix("excat_")))

    def __call__(self) -> dict[str, Any]:
        data = load_config_file()
        out: dict[str, Any] = {}
        for name, value in data.items():
            if name not in self.settings_cls.model_fields:
                continue  # compose/run.sh-level keys (ports, outbound proxy, …) are read by run.sh
            env = f"EXCAT_{name.upper()}"
            if isinstance(value, dict):
                value = {k: v for k, v in value.items() if not self._explicit(f"{env}__{str(k).upper()}")}
                if value:
                    out[name] = value
            elif not self._explicit(env):
                out[name] = value
        return out


class Features(BaseModel):
    """Feature flags for the 1.4 enhancements. All default off; off = exactly the previous behaviour."""

    ui_tls_management: bool = Field(False, description="Settings → Certificates & Domain: install/CSR/rollback.")
    acme: bool = Field(False, description="Allow ACME / Let's Encrypt certificates (internet-reachable hosts).")
    subscriptions: bool = Field(False, description="Threat Intel & News Subscriptions (paid sources, manual intel).")
    run_watch_mode: bool = Field(False, description="`./run.sh watch`: poll for changes and apply them (dev/test).")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EXCAT_", env_file=".env", env_file_encoding="utf-8", extra="ignore",
        env_nested_delimiter="__",  # EXCAT_FEATURES__UI_TLS_MANAGEMENT=true
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

    # --- Domain / deployment (1.4) -------------------------------------------------------------
    fqdn: str | None = Field(
        None, description="Public hostname (e.g. `exposurecatalyst.company.com`). When set, the public URL becomes "
        "`https://<fqdn>[:https_port]` and drives SAML/OIDC URLs, email links, allowed hosts and CSRF origins. "
        "Unset = previous behaviour (EXCAT_PUBLIC_URL). The Docker deployment defaults it to `localhost`.")
    https_port: int | None = Field(None, ge=1, le=65535, description="External HTTPS port (default 443).")
    http_port: int | None = Field(None, ge=1, le=65535, description="External HTTP port that redirects to HTTPS "
                                  "(Docker; default 80).")
    tls_mode: Literal["self-signed", "uploaded", "acme"] = Field(
        "self-signed", description="Docker proxy certificate source (see Settings → Certificates & Domain).")
    hsts: bool | None = Field(None, description="Send Strict-Transport-Security. Unset = previous behaviour "
                              "(sent when EXCAT_COOKIE_SECURE is true).")
    hsts_max_age_seconds: int = Field(63_072_000, ge=0, description="HSTS max-age (default two years).")
    trusted_proxies: str = Field("", description="Load balancers in front of the Docker proxy whose X-Forwarded-* "
                                 "headers are trusted (CIDRs; read by run.sh/compose).")
    outbound_proxy: str = Field("", description="Corporate HTTP(S) proxy for outbound calls (exported as "
                                "HTTPS_PROXY/HTTP_PROXY by run.sh).")
    timezone: str = Field("UTC", description="Container timezone for logs (TZ). The app stores and computes in UTC.")
    deployment: Literal["standalone", "docker"] = Field(
        "standalone", description="Set to `docker` by docker-compose; enables Docker-only defaults (fqdn=localhost).")
    certs_dir: Path = Field(Path("/var/lib/excat/certs"), description="Docker certs volume (proxy certificate, "
                            "trusted CA bundle). Absent outside Docker.")
    setup_token_hours: int = Field(24, ge=1, le=168, description="Validity of the first-run setup token.")
    bootstrap_admin: bool = Field(True, description="Docker: on an empty installation create the default break-glass "
                                  "Super Admin with the generated password from the secrets volume (password change + "
                                  "MFA enrolment forced at first sign-in). false = setup-token wizard instead.")
    bootstrap_admin_username: str = Field("breakglass", min_length=3, max_length=150,
                                          description="Username of the default break-glass account.")
    secrets_dir: Path = Field(Path("/var/lib/excat/secrets"), description="Docker secrets volume (generated by init).")
    config_file: str | None = Field(None, description="Path to the YAML config file. Read only when set "
                                    "(docker compose / run.sh point it at config/exposurecatalyst.yaml).")
    features: Features = Field(default_factory=Features, description="Feature flags (`features.<name>` in YAML, "
                               "`EXCAT_FEATURES__<NAME>` in the environment).")

    # --- Database ----------------------------------------------------------------------------
    database_url: SecretStr = Field(
        SecretStr("sqlite:///./exposurecatalyst.db"),
        description="SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host:5432/excat?sslmode=require`. "
        "SQLite is for development only.",
    )
    database_password: SecretStr | None = Field(
        None,
        description="Database password injected separately (e.g. ECS secret from the RDS-managed secret's "
        "`password` field). When set, it is inserted into EXCAT_DATABASE_URL, which then needs no password.",
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
    encryption_keys_previous: SecretStr | None = Field(
        None,
        description="Comma-separated previous Fernet keys, accepted for decryption during key rotation "
        "(see `exposurecatalyst rotate-secrets`). Remove once rotation has completed.",
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

    # --- Security News ------------------------------------------------------------------------
    news_interval_minutes: int = Field(30, ge=5, description="Default refresh interval for news feeds.")
    news_retention_days: int = Field(90, ge=7, description="Delete news items older than this.")
    news_max_items_per_feed: int = Field(100, ge=10, description="Newest items processed per feed per run.")

    # --- AI ------------------------------------------------------------------------------------
    ai_timeout_seconds: float = Field(90.0, gt=0, description="Timeout for AI provider calls.")
    ai_max_context_chars: int = Field(24_000, ge=2_000, description="Maximum untrusted context characters sent per AI request.")
    ai_allow_private_endpoints: bool = Field(
        False, description="Allow self-hosted AI endpoints (Ollama, vLLM, LM Studio) on private/loopback addresses."
    )
    ai_rate_limit_per_user_per_minute: int = Field(20, ge=1, description="AI requests allowed per user per minute.")

    # --- Retention ------------------------------------------------------------------------------
    retention_sessions_days: int = Field(30, ge=1, description="Delete expired or revoked sessions older than this.")
    retention_job_runs_days: int = Field(90, ge=7, description="Delete ingestion job-run history older than this.")
    retention_ai_usage_days: int = Field(400, ge=30, description="Delete AI usage records older than this (13 months default).")
    retention_alert_events_days: int = Field(365, ge=30, description="Delete delivered alert events older than this.")

    # --- Paths -------------------------------------------------------------------------------
    frontend_dist_dir: Path = Field(PROJECT_ROOT / "frontend" / "dist", description="Built React app served at /.")
    docs_site_dir: Path = Field(PROJECT_ROOT / "dist" / "docs" / "site", description="Built MkDocs site served at /docs.")
    docs_exports_dir: Path = Field(PROJECT_ROOT / "dist" / "docs" / "exports",
                                   description="DOCX / standalone HTML guides offered in Help Center → Download documentation.")
    help_dir: Path = Field(PROJECT_ROOT / "docs" / "help", description="In-app help Markdown (single source with docs).")
    brand_dir: Path = Field(PROJECT_ROOT / "brand", description="Brand kit (logos, tokens) used in emails, exports and docs.")
    changelog_path: Path = Field(PROJECT_ROOT / "CHANGELOG.md", description="Changelog shown in Help Center → What's new.")

    # ---------------------------------------------------------------------------------------
    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings,
                                   file_secret_settings):
        dotenv = dotenv_settings() if callable(dotenv_settings) else {}
        files = FileSecretsSource(settings_cls, dotenv)
        yaml_cfg = YamlConfigSource(settings_cls, dotenv)
        # files and YAML sit first but only fill gaps (no non-empty env/.env value), so explicit values win
        return init_settings, files, yaml_cfg, env_settings, dotenv_settings, file_secret_settings

    @property
    def cors_origin_list(self) -> list[str]:
        return _csv(self.cors_origins)

    @property
    def allowed_origins(self) -> set[str]:
        origins = {self.public_url, *([self.explicit_public_url] if self.explicit_public_url else [])}
        out = set()
        for o in origins:
            parts = urlsplit(o)
            out.add(f"{parts.scheme}://{parts.netloc}")
        return out | set(self.cors_origin_list)

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

    @field_validator("fqdn", "https_port", "http_port", "hsts", mode="before")
    @classmethod
    def _empty_is_unset(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("fqdn")
    @classmethod
    def _valid_fqdn(cls, v: str | None) -> str | None:
        if v is None:
            return None
        import re

        v = v.strip().lower().rstrip(".")
        if "://" in v or "/" in v or ":" in v:
            raise ValueError("fqdn is a bare hostname (no scheme, port or path), e.g. exposurecatalyst.company.com")
        if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", v):
            raise ValueError(f"fqdn '{v}' is not a valid hostname")
        return v

    @model_validator(mode="after")
    def _derive_public_url(self) -> Settings:
        """FQDN drives the public URL. Unset (outside Docker) → EXCAT_PUBLIC_URL exactly as before."""
        self._explicit_public_url = None
        if self.fqdn is None and self.deployment == "docker":
            self.fqdn = "localhost"
        if self.fqdn is not None:
            port = self.https_port or 443
            derived = f"https://{self.fqdn}" + ("" if port == 443 else f":{port}")
            if "public_url" in self.model_fields_set and self.public_url.rstrip("/") != derived:
                self._explicit_public_url = self.public_url.rstrip("/")  # kept as an extra trusted origin
            self.public_url = derived
        return self

    @property
    def explicit_public_url(self) -> str | None:
        """EXCAT_PUBLIC_URL when the FQDN overrides it (e.g. the `direct` profile on http://localhost:8000)."""
        return getattr(self, "_explicit_public_url", None)

    @property
    def allowed_hosts(self) -> list[str] | None:
        """Host-header allowlist when an FQDN is set (None = no restriction, the previous behaviour)."""
        if self.fqdn is None:
            return None
        hosts = {self.fqdn, "localhost", "127.0.0.1", "::1", "api"}
        if self.explicit_public_url:
            hosts.add(urlsplit(self.explicit_public_url).hostname or "")
        hosts |= {urlsplit(o).hostname or "" for o in self.cors_origin_list}
        return sorted(h for h in hosts if h)

    @property
    def hsts_enabled(self) -> bool:
        return self.cookie_secure if self.hsts is None else self.hsts

    @model_validator(mode="after")
    def _merge_db_password(self) -> Settings:
        if self.database_password is not None:
            from sqlalchemy.engine import make_url

            url = make_url(self.database_url.get_secret_value()).set(password=self.database_password.get_secret_value())
            self.database_url = SecretStr(url.render_as_string(hide_password=False))
        return self

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

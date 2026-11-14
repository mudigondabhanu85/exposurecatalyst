from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from exposurecatalyst.db.base import Base, utcnow


class GroupRoleMapping(Base):
    """SailPoint/Okta group name → ExposureCatalyst role. SSO users' roles are derived only from these."""

    __tablename__ = "group_role_mappings"
    __table_args__ = (UniqueConstraint("group_name", "role_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_name: Mapped[str] = mapped_column(String(255), index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SamlRequest(Base):
    """Outstanding SP-initiated AuthnRequests: a response is accepted only for an unused, recent ID."""

    __tablename__ = "saml_requests"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    relay_state: Mapped[str] = mapped_column(String(500), default="/cves")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OidcRequest(Base):
    """Outstanding OIDC authorization requests (state → nonce + PKCE verifier), single use, short-lived.
    The state is stored hashed; the PKCE verifier is Fernet-encrypted."""

    __tablename__ = "oidc_requests"

    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128))
    code_verifier_enc: Mapped[str] = mapped_column(Text)
    relay_state: Mapped[str] = mapped_column(String(500), default="/cves")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SamlAssertion(Base):
    """Replay cache of consumed assertion IDs (kept until NotOnOrAfter)."""

    __tablename__ = "saml_assertions"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    not_on_or_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScimToken(Base):
    __tablename__ = "scim_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256; the token is shown once
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScimGroup(Base):
    __tablename__ = "scim_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), unique=True)
    external_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ScimGroupMember(Base):
    __tablename__ = "scim_group_members"

    group_id: Mapped[str] = mapped_column(ForeignKey("scim_groups.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    criteria: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    recipients: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # emails, user_ids, role_ids
    channels: Mapped[list[str]] = mapped_column(JSON, default=list)  # email | slack | teams
    webhooks_enc: Mapped[str | None] = mapped_column(Text)  # Fernet JSON {"slack": url, "teams": url}
    mode: Mapped[str] = mapped_column(String(16), default="immediate")  # immediate | digest
    throttle_minutes: Mapped[int] = mapped_column(Integer, default=60)
    digest_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    cursor_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AlertEvent(Base):
    """One CVE matched by one rule (never notified twice)."""

    __tablename__ = "alert_events"
    __table_args__ = (UniqueConstraint("rule_id", "cve_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rules.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(String(300))
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | sent | error

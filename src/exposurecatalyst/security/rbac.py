"""Permission catalogue and default roles.

This module is the single source of truth for RBAC: the API enforces it, the seeder writes it,
and the docs build renders the roles × permissions matrix from it.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.models import Role, RolePermission, User


class Permission(StrEnum):
    CVE_VIEW = "cve:view"
    CVE_REFRESH = "cve:refresh"
    ADVISORY_CREATE = "advisory:create"
    ADVISORY_APPROVE = "advisory:approve"
    ADVISORY_SEND = "advisory:send"
    ADVISORY_EXPORT = "advisory:export"
    TEMPLATE_MANAGE = "template:manage"
    NEWS_VIEW = "news:view"
    NEWS_MANAGE = "news:manage"
    SOURCE_MANAGE = "source:manage"
    INTEGRATION_MANAGE = "integration:manage"
    SETTINGS_MANAGE = "settings:manage"
    SSO_MANAGE = "sso:manage"
    USER_MANAGE = "user:manage"
    ROLE_MANAGE = "role:manage"
    AI_USE = "ai:use"
    AI_MANAGE = "ai:manage"
    AUDIT_VIEW = "audit:view"
    INTEL_MANAGE = "intel:manage"  # 1.4: manual intel items, bulk import (subscriptions)


PERMISSION_DESCRIPTIONS: dict[Permission, str] = {
    Permission.CVE_VIEW: "View CVEs, CVE details, source health and saved searches",
    Permission.CVE_REFRESH: "Trigger a manual 'Refresh now' of CVE sources",
    Permission.ADVISORY_CREATE: "Create and edit advisory email drafts",
    Permission.ADVISORY_APPROVE: "Approve advisories and templates (cannot approve own work)",
    Permission.ADVISORY_SEND: "Send approved advisories via SMTP",
    Permission.ADVISORY_EXPORT: "Download .eml / HTML / PDF / Excel exports",
    Permission.TEMPLATE_MANAGE: "Create and version advisory templates",
    Permission.NEWS_VIEW: "View the Security News feed",
    Permission.NEWS_MANAGE: "Add or remove news feeds",
    Permission.SOURCE_MANAGE: "Enable/disable CVE sources and change fetch intervals",
    Permission.INTEGRATION_MANAGE: "Configure security-tool connectors and credentials",
    Permission.SETTINGS_MANAGE: "Manage database, SMTP and alert settings",
    Permission.SSO_MANAGE: "Configure Okta SAML / OIDC and SailPoint mappings",
    Permission.USER_MANAGE: "Create users, assign roles, unlock accounts",
    Permission.ROLE_MANAGE: "Create and edit custom roles",
    Permission.AI_USE: "Use AI summaries, drafting and assistant",
    Permission.AI_MANAGE: "Configure AI providers, allowlist and redaction policy",
    Permission.AUDIT_VIEW: "View the immutable audit log",
    Permission.INTEL_MANAGE: "Add manual intel items, import intel bundles and view TLP:RED subscription intel",
}

P = Permission
ALL = frozenset(Permission)

# Segregation of duties: Admins run the platform but cannot approve/send advisories;
# Approvers approve but cannot create or send; Analysts create/send but cannot approve.
DEFAULT_ROLES: dict[str, tuple[str, frozenset[Permission]]] = {
    "Super Admin": ("Full control, including roles and SSO. Break-glass only.", ALL),
    "Admin": (
        "Operates the platform: sources, integrations, settings, users. No advisory approval or send.",
        frozenset({
            P.CVE_VIEW, P.CVE_REFRESH, P.NEWS_VIEW, P.NEWS_MANAGE, P.SOURCE_MANAGE,
            P.INTEGRATION_MANAGE, P.SETTINGS_MANAGE, P.USER_MANAGE, P.AI_MANAGE,
            P.TEMPLATE_MANAGE, P.AUDIT_VIEW, P.INTEL_MANAGE,
        }),
    ),
    "Security Analyst": (
        "Triages CVEs and prepares, exports and sends approved advisories.",
        frozenset({
            P.CVE_VIEW, P.CVE_REFRESH, P.ADVISORY_CREATE, P.ADVISORY_SEND, P.ADVISORY_EXPORT,
            P.NEWS_VIEW, P.AI_USE, P.INTEL_MANAGE,
        }),
    ),
    "Approver": (
        "Reviews and approves advisories and templates.",
        frozenset({P.CVE_VIEW, P.ADVISORY_APPROVE, P.ADVISORY_EXPORT, P.NEWS_VIEW, P.AI_USE}),
    ),
    "Viewer": ("Read-only access to CVEs and news.", frozenset({P.CVE_VIEW, P.NEWS_VIEW})),
    "Auditor": ("Read-only plus the audit log.", frozenset({P.CVE_VIEW, P.NEWS_VIEW, P.AUDIT_VIEW})),
}

ADMIN_PERMISSIONS = frozenset({
    P.SOURCE_MANAGE, P.INTEGRATION_MANAGE, P.SETTINGS_MANAGE, P.SSO_MANAGE,
    P.USER_MANAGE, P.ROLE_MANAGE, P.AI_MANAGE,
})


def user_permissions(user: User) -> set[str]:
    if not user.is_active:
        return set()
    perms: set[str] = set()
    for role in user.roles:
        perms |= role.permission_names
    return perms


def seed_roles(db: Session) -> None:
    """Create system roles and keep their permissions in sync with DEFAULT_ROLES (idempotent)."""
    existing = {r.name: r for r in db.scalars(select(Role)).all()}
    for name, (description, perms) in DEFAULT_ROLES.items():
        role = existing.get(name)
        if role is None:
            role = Role(name=name, description=description, is_system=True)
            db.add(role)
        role.is_system = True
        role.description = description
        wanted = {str(p) for p in perms}
        current = {rp.permission: rp for rp in role.permissions}
        for perm in wanted - current.keys():
            role.permissions.append(RolePermission(permission=perm))
        for perm in current.keys() - wanted:
            role.permissions.remove(current[perm])
    db.flush()

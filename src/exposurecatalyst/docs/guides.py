"""Audience guides exported as DOCX and standalone HTML. Shared by the export pipeline and the download API,
so it has no heavy imports."""

from __future__ import annotations

from dataclasses import dataclass

from exposurecatalyst.security.rbac import Permission

ADMIN_PERMISSIONS = frozenset({
    Permission.SETTINGS_MANAGE, Permission.USER_MANAGE, Permission.ROLE_MANAGE, Permission.SSO_MANAGE,
    Permission.INTEGRATION_MANAGE, Permission.SOURCE_MANAGE, Permission.AI_MANAGE, Permission.NEWS_MANAGE,
    Permission.TEMPLATE_MANAGE,
})


@dataclass(frozen=True)
class Guide:
    id: str
    title: str
    description: str
    sections: tuple[str, ...] | None  # top-level nav sections included; None = the whole site
    pages: tuple[str, ...] = ()       # extra individual pages (docs-relative paths)
    any_of: frozenset[str] = frozenset()  # download requires at least one of these permissions (empty = any user)

    def allowed(self, permissions: set[str] | frozenset[str]) -> bool:
        return not self.any_of or bool(self.any_of & set(permissions))


USER_HELP = ("help/help-center.md", "help/cve-intelligence.md", "help/cve-detail.md", "help/advisories.md",
             "help/advisory-editor.md", "help/news.md", "help/assistant.md", "help/glossary.md", "help/faq.md",
             "help/shortcuts.md")
ADMIN_HELP = ("help/advisory-templates.md", "help/settings-smtp.md", "help/settings-integrations.md",
              "help/settings-sso.md", "help/settings-alerts.md", "help/settings-news.md", "help/settings-ai.md",
              "help/settings-sources.md", "help/settings-rbac.md", "help/settings-database.md",
              "help/settings-certificates.md")

GUIDES: tuple[Guide, ...] = (
    Guide("user", "User Guide", "CVE Intelligence, advisories, news and the assistant — for analysts, approvers "
          "and viewers.", ("Home", "User guide"), USER_HELP),
    Guide("admin", "Administrator Guide", "Installation, configuration, identity, integrations, operations and "
          "runbooks.", ("Getting started", "Admin guide", "Integrations", "Reference", "Operations"), ADMIN_HELP,
          ADMIN_PERMISSIONS),
    Guide("security", "Security & Architecture Guide", "AWS architecture, network, data flows, STRIDE threat "
          "model, controls mapping, DR and decision records.", ("Architecture", "Security"),
          ("operations/disaster-recovery.md", "operations/monitoring.md", "reference/rbac-matrix.md"),
          ADMIN_PERMISSIONS | {Permission.AUDIT_VIEW}),
    Guide("full", "Complete Guide", "Every page of the documentation in one document.", None, (),
          frozenset({Permission.SETTINGS_MANAGE})),
)
GUIDES_BY_ID = {g.id: g for g in GUIDES}
FORMATS = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
           "html": "text/html; charset=utf-8"}


def export_filename(guide_id: str, fmt: str) -> str:
    return f"exposurecatalyst-{guide_id}-guide.{fmt}"

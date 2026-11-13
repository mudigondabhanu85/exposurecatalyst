"""Logical / component architecture of the application."""

from __future__ import annotations

from pathlib import Path

from _aws_style import (BRAND_BODY_FONT, COLUMN, DIAGRAM_ATTRS, GROUP, cluster_label, flow, label, legend_html,
                        node_attrs, title_block)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.database import Aurora
from diagrams.aws.general import Users
from diagrams.aws.security import SecretsManager
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.programming.framework import Fastapi, React
from diagrams.programming.language import Python

AUTO_DRAWIO = True
NAME = "components"
TITLE = "ExposureCatalyst — Logical Component Architecture"
SUBTITLE = "Presentation · API (auth/RBAC on every route) · domain services · background engines · data"


def C(title: str, detail: str):  # noqa: N802
    return Python(label(title, detail), **node_attrs())


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE), "ranksep": "1.2"}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        users = Users(label("Users"), **node_attrs())
        with Cluster("ui", graph_attr={**GROUP["layer"], **COLUMN, "label": cluster_label("Presentation")}):
            spa = React(label("React SPA", "tabs · help drawer · tours · tooltips"), **node_attrs())
        with Cluster("api", graph_attr={**GROUP["private"], **COLUMN, "label": cluster_label("API (FastAPI)")}):
            gw = Fastapi(label("Routers", "CVEs · advisories · news · integrations · AI · settings · SCIM"), **node_attrs())
            authz = C("Auth & RBAC", "sessions · CSRF · SAML SP · require(permission)")
            audit = C("Audit", "hash-chained, append-only")
            helpc = C("Help service", "RBAC-filtered Markdown")
        with Cluster("domain", graph_attr={**GROUP["layer"], **COLUMN, "label": cluster_label("Domain services")}):
            adv = C("Email engine", "templates (sandbox) · MIME · Excel · PDF")
            corr = C("Connector framework", "Qualys · Tanium · Wiz · Zafran · ArmorCode · CMDB")
            aisvc = C("AI adapter", "routing · fallback · redaction · usage")
        with Cluster("bg", graph_attr={**GROUP["layer"], **COLUMN, "label": cluster_label("Background engines")}):
            sched = C("Scheduler tick", "claims due sources (DB lock)")
            ingest = C("Ingestion", "NVD · KEV · EPSS · news")
            alerts = C("Alert engine", "rules · throttle · digest")
            maint = C("Maintenance", "retention · key rotation")
        with Cluster("data", graph_attr={**GROUP["isolated"], **COLUMN, "label": cluster_label("Data")}):
            db = Aurora(label("Relational DB", "PostgreSQL / MySQL / SQL Server / Oracle"), **node_attrs())
            s3 = SimpleStorageServiceS3Bucket(label("Object storage", "exports · archives"), **node_attrs())
            sec = SecretsManager(label("Secrets", "Fernet key · DB creds"), **node_attrs())
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11", fixedsize="false", height="0", width="0")

        users >> flow("sync", "HTTPS") >> spa
        spa >> flow("sync", "JSON API + CSRF header") >> gw
        gw >> flow("sync", "every request") >> authz
        gw >> flow("sync", "state changes") >> audit
        gw >> flow("sync", "help topics", constraint=False) >> helpc
        gw >> flow("sync", "advisories") >> adv
        gw >> flow("sync", "check / pull assets") >> corr
        gw >> flow("sync", "AI features") >> aisvc
        sched >> flow("async", "due sources") >> ingest
        sched >> flow("async", "after each tick") >> alerts
        sched >> flow("async", "daily") >> maint
        alerts >> flow("sync", "email / webhooks", constraint=False) >> adv
        for comp in (authz, audit, adv, corr, aisvc, ingest, alerts, maint):
            comp >> flow("sync", "SQLAlchemy", constraint=False) >> db
        adv >> flow("sync", "exports") >> s3
        sec >> flow("mgmt", "secrets at start", constraint=False) >> gw
        legend >> Edge(style="invis") >> users

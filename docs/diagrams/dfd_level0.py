"""Data-flow diagram, Level 0 (context) — trust boundaries and data classification."""

from __future__ import annotations

from pathlib import Path

from _aws_style import (BRAND_BODY_FONT, COLUMN, DIAGRAM_ATTRS, GROUP, cluster_label, flow, label, legend_html,
                        node_attrs, title_block)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.compute import Fargate
from diagrams.aws.database import Aurora
from diagrams.aws.general import InternetAlt1, Users
from diagrams.aws.security import SecretsManager
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.saas.identity import Okta

AUTO_DRAWIO = True
NAME = "dfd_level0"
TITLE = "ExposureCatalyst — Data Flow Diagram, Level 0"
SUBTITLE = "Context view · red dashed = trust boundary · [classification] on every flow"


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE), "ranksep": "1.6"}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        with Cluster("tb_users", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB1 — Corporate users (browser)")}):
            users = Users(label("Analysts · Approvers · Admins · Viewers"), **node_attrs())
        with Cluster("tb_idp", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB2 — Identity providers")}):
            okta = Okta(label("Okta (SAML)"), **node_attrs())
            sail = InternetAlt1(label("SailPoint (SCIM)"), **node_attrs())
        with Cluster("tb_public", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB3 — Public internet sources")}):
            src = InternetAlt1(label("CVE sources & news feeds", "NVD · KEV · EPSS · RSS"), **node_attrs())
        with Cluster("tb_tools", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB4 — Security tools (SaaS / on-prem)")}):
            tools = InternetAlt1(label("Qualys · Tanium · Wiz · Zafran · ArmorCode · ServiceNow"), **node_attrs())
        with Cluster("tb_aws", graph_attr={**GROUP["trust"], "label": cluster_label("TB5 — ExposureCatalyst AWS account")}):
            app = Fargate(label("0 — ExposureCatalyst", "web · API · workers"), **node_attrs())
            with Cluster("stores", graph_attr={**GROUP["isolated"], **COLUMN, "label": cluster_label("Data stores")}):
                db = Aurora(label("D — Platform DB", "CVEs · assets · advisories · users · audit"), **node_attrs())
                s3 = SimpleStorageServiceS3Bucket(label("D — Exports", "Excel · email archive"), **node_attrs())
                sm = SecretsManager(label("D — Secrets", "keys · credentials"), **node_attrs())
        with Cluster("tb_out", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB6 — Outbound recipients & processors")}):
            mail = InternetAlt1(label("Email recipients", "SMTP / SES · Slack · Teams"), **node_attrs())
            ai = InternetAlt1(label("AI providers (optional)"), **node_attrs())
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11", fixedsize="false", height="0", width="0")

        users >> flow("sync", "UI/API requests, session cookie", data="Confidential") >> app
        okta >> flow("ext", "signed SAML assertion", data="Restricted") >> app
        sail >> flow("ext", "SCIM users & groups (bearer)", data="Confidential") >> app
        src >> flow("egress", "CVE / KEV / EPSS / news", data="Public") >> app
        tools >> flow("egress", "affected assets", data="Confidential") >> app
        app >> flow("sync", "read/write", data="Confidential") >> db
        app >> flow("sync", "exports", data="Confidential") >> s3
        sm >> flow("mgmt", "credentials (decrypt in memory)", data="Restricted") >> app
        app >> flow("egress", "advisories, Excel, alerts", data="Confidential") >> mail
        app >> flow("egress", "prompts — identifiers redacted", data="Internal") >> ai
        legend >> Edge(style="invis") >> users

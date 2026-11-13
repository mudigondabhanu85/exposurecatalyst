"""Data-flow diagram, Level 1 — the six core flows with trust boundaries and data classification."""

from __future__ import annotations

from pathlib import Path

from _aws_style import (BRAND_BODY_FONT, COLUMN, DIAGRAM_ATTRS, GROUP, cluster_label, flow, label, legend_html,
                        node_attrs, title_block)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.compute import ElasticContainerServiceService
from diagrams.aws.database import Aurora
from diagrams.aws.general import InternetAlt1, Users
from diagrams.aws.security import SecretsManager
from diagrams.aws.storage import SimpleStorageServiceS3Bucket

AUTO_DRAWIO = True
NAME = "dfd_level1"
TITLE = "ExposureCatalyst — Data Flow Diagram, Level 1"
SUBTITLE = "Processes 1–6 · data stores D1–D6 · trust boundaries TB1–TB6 · [classification] on every flow"


def P(n: str, title: str, detail: str):  # noqa: N802 - DFD process
    return ElasticContainerServiceService(label(f"{n} {title}", detail), **node_attrs())


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE), "ranksep": "1.4"}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        with Cluster("tb_ext_in", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB3/TB4 — External sources")}):
            cve_src = InternetAlt1(label("CVE sources", "NVD · KEV · EPSS"), **node_attrs())
            feeds = InternetAlt1(label("News feeds", "RSS / Atom"), **node_attrs())
            tools = InternetAlt1(label("Security tools", "Qualys · Tanium · Wiz · …"), **node_attrs())
        with Cluster("tb_users", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB1 — Users")}):
            analyst = Users(label("Analyst"), **node_attrs())
            approver = Users(label("Approver"), **node_attrs())
        with Cluster("tb_app", graph_attr={**GROUP["trust"], "label": cluster_label("TB5 — Application (ECS, private subnets)")}):
            with Cluster("procs", graph_attr={**GROUP["private"], **COLUMN, "label": cluster_label("Processes")}):
                p1 = P("1", "CVE ingestion & normalization", "SSRF guard · rate limit · provenance")
                p6 = P("6", "News ingestion", "defusedxml · excerpt only · dedup")
                p2 = P("2", "Asset correlation", "per-tool isolation · field mapping · CMDB enrich")
                p3 = P("3", "Advisory create → approve → send/export", "sandboxed templates · SoD")
                p4 = P("4", "Alert evaluation → notification", "cursor · throttle · digest")
                p5 = P("5", "AI request with redaction", "fence · redact · validate · restore")
            with Cluster("tb_data", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB5b — Data tier (isolated subnets / KMS)")}):
                d1 = Aurora(label("D1 CVE store", "Public"), **node_attrs())
                d2 = Aurora(label("D2 Asset findings", "Confidential"), **node_attrs())
                d3 = Aurora(label("D3 Advisories · deliveries · audit", "Confidential"), **node_attrs())
                d4 = SecretsManager(label("D4 Secrets", "Restricted"), **node_attrs())
                d5 = SimpleStorageServiceS3Bucket(label("D5 Exports", "Confidential"), **node_attrs())
                d6 = Aurora(label("D6 News items", "Public"), **node_attrs())
        with Cluster("tb_out", graph_attr={**GROUP["trust"], **COLUMN, "label": cluster_label("TB6 — Outbound")}):
            smtp = InternetAlt1(label("Recipients", "SMTP/SES · Slack · Teams"), **node_attrs())
            llm = InternetAlt1(label("AI provider", "allowlisted"), **node_attrs())
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11", fixedsize="false", height="0", width="0")

        cve_src >> flow("egress", "HTTPS pull, allowlisted", data="Public") >> p1
        p1 >> flow("sync", "upsert + provenance + timeline", data="Public") >> d1
        feeds >> flow("egress", "HTTPS pull, single-host", data="Public") >> p6
        p6 >> flow("sync", "headline + ≤300-char excerpt", data="Public") >> d6
        tools >> flow("egress", "assets for CVE (read-only token)", data="Confidential") >> p2
        d4 >> flow("mgmt", "tool credentials", data="Restricted", constraint=False) >> p2
        p2 >> flow("sync", "normalized findings", data="Confidential") >> d2
        analyst >> flow("sync", "draft, recipients, assets", data="Confidential") >> p3
        approver >> flow("sync", "approve (≠ author)", data="Internal") >> p3
        d2 >> flow("sync", "findings", data="Confidential", constraint=False) >> p3
        p3 >> flow("sync", "advisory, deliveries, audit", data="Confidential") >> d3
        p3 >> flow("sync", "Excel / .eml archive", data="Confidential") >> d5
        p3 >> flow("egress", "SMTP/TLS advisory + Excel", data="Confidential") >> smtp
        d1 >> flow("async", "changed CVEs since cursor", data="Public", constraint=False) >> p4
        p4 >> flow("egress", "alert digest (webhooks encrypted)", data="Internal") >> smtp
        analyst >> flow("sync", "AI request", data="Internal") >> p5
        d2 >> flow("sync", "exposure sample", data="Confidential", constraint=False) >> p5
        p5 >> flow("egress", "prompt — hostnames/IPs/owners redacted", data="Internal") >> llm
        llm >> flow("ext", "untrusted output → validated", data="Untrusted", constraint=False) >> p5
        legend >> Edge(style="invis") >> cve_src

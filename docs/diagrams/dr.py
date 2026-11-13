"""Multi-region disaster recovery — Aurora Global Database, S3 CRR, Route 53 failover (warm standby)."""

from __future__ import annotations

from pathlib import Path

from _aws_style import (BRAND_BODY_FONT, COLUMN, DIAGRAM_ATTRS, GROUP, cluster_label, flow, label, legend_html,
                        node_attrs, title_block)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.compute import Fargate
from diagrams.aws.database import Aurora
from diagrams.aws.general import Users
from diagrams.aws.network import CloudFront, ElbApplicationLoadBalancer, Route53
from diagrams.aws.security import KMS, SecretsManager
from diagrams.aws.storage import SimpleStorageServiceS3Bucket

AUTO_DRAWIO = True
NAME = "dr"
TITLE = "ExposureCatalyst — Multi-Region Disaster Recovery"
SUBTITLE = "Warm standby · RPO ≈ 1 s (Aurora Global) / 15 min (S3 RTC) · RTO ≈ 30 min"


def region(name: str, primary: bool):
    tag = "primary" if primary else "standby"
    with Cluster(f"r_{tag}", graph_attr={**GROUP["region"], "label": cluster_label(name, "Primary — active" if primary else "Secondary — warm standby")}):
        with Cluster(f"app_{tag}", graph_attr={**GROUP["private"], **COLUMN, "label": cluster_label("Application")}):
            alb = ElbApplicationLoadBalancer(label("ALB", "health check /api/health/ready"), **node_attrs())
            ecs = Fargate(label("ECS services", "desired 2+ / AZ" if primary else "desired 1 (scale on failover)"), **node_attrs())
        with Cluster(f"data_{tag}", graph_attr={**GROUP["isolated"], **COLUMN, "label": cluster_label("Data")}):
            db = Aurora(label("Aurora Global — " + ("primary (RW)" if primary else "secondary (RO)"), "Aurora PostgreSQL"), **node_attrs())
            s3 = SimpleStorageServiceS3Bucket(label("Exports / archives", "S3 versioned, SSE-KMS"), **node_attrs())
        with Cluster(f"sec_{tag}", graph_attr={**GROUP["security"], **COLUMN, "label": cluster_label("Keys & secrets")}):
            sm = SecretsManager(label("Secrets", "replica secret" if not primary else "primary secret"), **node_attrs())
            kms = KMS(label("Multi-Region key", "mrk-… replica" if not primary else "mrk-… primary"), **node_attrs())
    return alb, ecs, db, s3, sm, kms


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE)}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        users = Users(label("Users"), **node_attrs())
        with Cluster("aws", graph_attr={**GROUP["aws_cloud"], "label": cluster_label("AWS Cloud")}):
            with Cluster("global", graph_attr={**GROUP["layer"], **COLUMN, "label": cluster_label("Global")}):
                r53 = Route53(label("Failover records", "health-checked primary / secondary"), **node_attrs())
                cf = CloudFront(label("CDN", "origin group: primary → secondary"), **node_attrs())
            p = region("us-east-1", True)
            s = region("us-west-2", False)
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11", fixedsize="false", height="0", width="0")

        users >> flow("sync", "① DNS + HTTPS") >> r53
        r53 >> flow("sync", "② alias → CloudFront") >> cf
        cf >> flow("sync", "③ primary origin") >> p[0]
        cf >> flow("egress", "④ failover origin (5xx / health)") >> s[0]
        p[0] >> flow("sync", "HTTPS") >> p[1]
        s[0] >> flow("sync", "HTTPS") >> s[1]
        p[1] >> flow("sync", "SQL/TLS") >> p[2]
        s[1] >> flow("sync", "reads; writes after promotion") >> s[2]
        p[2] >> flow("async", "⑤ storage replication < 1 s (Global Database)", constraint=False) >> s[2]
        p[3] >> flow("async", "⑥ S3 CRR + Replication Time Control", constraint=False) >> s[3]
        p[4] >> flow("async", "⑦ secret replication", constraint=False) >> s[4]
        p[5] >> flow("mgmt", "multi-Region key replica", constraint=False) >> s[5]
        legend >> Edge(style="invis") >> users

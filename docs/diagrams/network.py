"""Network architecture — VPC, subnets per AZ, endpoints, NAT, Network Firewall egress allowlist."""

from __future__ import annotations

from pathlib import Path

from _aws_style import (BRAND_BODY_FONT, COLUMN, DIAGRAM_ATTRS, GROUP, cluster_label, flow, label, legend_html,
                        node_attrs, title_block)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.compute import Fargate
from diagrams.aws.database import Aurora, ElasticacheForRedis
from diagrams.aws.general import InternetAlt1, Users
from diagrams.aws.network import CloudFront, ElbApplicationLoadBalancer, Endpoint, InternetGateway, NATGateway, NetworkFirewall

AUTO_DRAWIO = True
NAME = "network"
TITLE = "ExposureCatalyst — Network Architecture"
SUBTITLE = "VPC 10.20.0.0/16 · 2 AZs · public / private / isolated tiers · egress only via Network Firewall"
ALLOWLIST = ("Egress allowlist (Network Firewall, TLS SNI):\\l"
             "services.nvd.nist.gov · www.cisa.gov · api.first.org · epss.empiricalsecurity.com\\l"
             "news feed hosts (Settings → News feeds)\\l"
             "integration hosts: *.qualys.com · *.app.wiz.io · *.cloud.tanium.com · *.service-now.com …\\l"
             "AI providers in the allowlist · SMTP relay / email-smtp.<region>.amazonaws.com\\l"
             "Okta metadata host · hooks.slack.com · *.webhook.office.com\\l"
             "Everything else: DROP + alert\\l")


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE)}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        with Cluster("ext", graph_attr={**GROUP["external"], **COLUMN, "label": cluster_label("Internet")}):
            users = Users(label("Users", "via CloudFront"), **node_attrs())
            dest = InternetAlt1(label("Allowlisted destinations", "CVE / news / tools / AI / SMTP"), **node_attrs())
        cf = CloudFront(label("Edge", "Amazon CloudFront + AWS WAF"), **node_attrs())
        with Cluster("aws", graph_attr={**GROUP["aws_cloud"], "label": cluster_label("AWS Cloud")}):
            with Cluster("region", graph_attr={**GROUP["region"], "label": cluster_label("Region us-east-1")}):
                with Cluster("vpc", graph_attr={**GROUP["vpc"], "label": cluster_label("VPC 10.20.0.0/16", "DNS hostnames on · flow logs → CloudWatch")}):
                    igw = InternetGateway(label("Internet gateway", "IGW"), **node_attrs())
                    vpce = Endpoint(label("VPC endpoints", "S3 (gateway) · Secrets Manager · KMS · SQS · Logs · ECR · STS"), **node_attrs())
                    tiers = {}
                    for az, cidr in (("a", 0), ("b", 1)):
                        with Cluster(f"az{az}", graph_attr={**GROUP["az"], "label": cluster_label(f"Availability Zone {az.upper()}")}):
                            with Cluster(f"pub{az}", graph_attr={**GROUP["public"], **COLUMN, "label": cluster_label("Public", f"10.20.{cidr}.0/24")}):
                                alb = ElbApplicationLoadBalancer(label("ALB node", "SG: 443 from CloudFront prefix list"), **node_attrs())
                                nat = NATGateway(label("NAT gateway", "per AZ"), **node_attrs())
                            with Cluster(f"fw{az}", graph_attr={**GROUP["security"], **COLUMN, "label": cluster_label("Firewall", f"10.20.{10 + cidr}.0/28")}):
                                nfw = NetworkFirewall(label("Firewall endpoint", "AWS Network Firewall"), **node_attrs())
                            with Cluster(f"app{az}", graph_attr={**GROUP["private"], **COLUMN, "label": cluster_label("Private app", f"10.20.{20 + cidr}.0/22")}):
                                tasks = Fargate(label("API / worker / scheduler", "ECS Fargate tasks · SG: 8000 from ALB"), **node_attrs())
                            with Cluster(f"data{az}", graph_attr={**GROUP["isolated"], **COLUMN, "label": cluster_label("Isolated data", f"10.20.{40 + cidr}.0/24 · no route to internet")}):
                                db = Aurora(label("Aurora " + ("writer" if az == "a" else "replica"), "SG: 5432 from app SG"), **node_attrs())
                                cache = ElasticacheForRedis(label("Redis " + ("primary" if az == "a" else "replica"), "SG: 6379 from app SG"), **node_attrs())
                        tiers[az] = (alb, nat, nfw, tasks, db, cache)
        with Cluster("rules", graph_attr={**GROUP["legend"], "label": cluster_label("Egress policy")}):
            Node(ALLOWLIST, shape="note", fontname=BRAND_BODY_FONT, fontsize="10", fixedsize="false", width="0", height="0",
                 color="#DD344C", fontcolor="#0B1B33")
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11", fixedsize="false", height="0", width="0")

        users >> flow("sync", "HTTPS 443") >> cf
        for az in ("a", "b"):
            alb, nat, nfw, tasks, db, cache = tiers[az]
            cf >> flow("sync", f"origin HTTPS (AZ-{az})") >> alb
            alb >> flow("sync", "8000/TLS") >> tasks
            tasks >> flow("sync", "5432 TLS") >> db
            tasks >> flow("sync", "6379 TLS", constraint=False) >> cache
            tasks >> flow("egress", "0.0.0.0/0 → firewall endpoint") >> nfw
            nfw >> flow("egress", "allowed SNI only") >> nat
            nat >> flow("egress", "SNAT") >> igw
            tasks >> flow("mgmt", "AWS APIs via PrivateLink", constraint=False) >> vpce
        tiers["a"][4] >> flow("async", "Multi-AZ storage replication", constraint=False) >> tiers["b"][4]
        igw >> flow("egress", "HTTPS 443") >> dest
        legend >> Edge(style="invis") >> users

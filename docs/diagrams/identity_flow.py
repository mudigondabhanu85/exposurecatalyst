"""Identity flow — Okta SAML 2.0 sign-in and SailPoint SCIM 2.0 provisioning → group → role RBAC.

Flow numbers ①–⑨ match docs/architecture/identity-flow.md.
"""

from __future__ import annotations

from pathlib import Path

from _aws_style import (
    BRAND_BODY_FONT,
    COLUMN,
    DIAGRAM_ATTRS,
    EDGE,
    GROUP,
    Drawio,
    cluster_label,
    edge_label,
    label,
    legend_html,
    node_attrs,
    title_block,
)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.compute import Fargate
from diagrams.aws.database import Aurora
from diagrams.aws.general import InternetAlt1, Users
from diagrams.aws.management import Cloudwatch
from diagrams.aws.network import CloudFront, ElbApplicationLoadBalancer
from diagrams.aws.security import KMS, WAF, SecretsManager
from diagrams.saas.identity import Okta

NAME = "identity_flow"
TITLE = "ExposureCatalyst — Identity Flow"
SUBTITLE = "Okta SAML 2.0 sign-in · SailPoint SCIM 2.0 provisioning · group → role RBAC"


def e(kind: str, text: str, constraint: bool = True, minlen: int = 1) -> Edge:
    attrs = dict(EDGE[kind])
    if not constraint:
        attrs["constraint"] = "false"
    if minlen > 1:
        attrs["minlen"] = str(minlen)
    return Edge(xlabel=edge_label(text), **attrs)


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE)}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        with Cluster("ext", graph_attr={**GROUP["external"], **COLUMN, "label": cluster_label("Identity providers", "Outside AWS")}):
            users = Users(label("Workforce users", "Browser"), **node_attrs())
            okta = Okta(label("Authentication + MFA", "Okta (SAML 2.0 IdP)"), **node_attrs())
            sailpoint = InternetAlt1(label("Identity governance", "SailPoint ISC / IIQ (SCIM 2.0 client)"), **node_attrs())
        with Cluster("aws", graph_attr={**GROUP["aws_cloud"], "label": cluster_label("AWS Cloud")}):
            with Cluster("edge", graph_attr={**GROUP["layer"], **COLUMN, "label": cluster_label("Edge")}):
                cf = CloudFront(label("CDN", "Amazon CloudFront"), **node_attrs())
                waf = WAF(label("Web ACL", "AWS WAF"), **node_attrs())
            with Cluster("region", graph_attr={**GROUP["region"], "label": cluster_label("Region", "VPC · private subnets")}):
                with Cluster("app", graph_attr={**GROUP["private"], **COLUMN, "label": cluster_label("Application layer")}):
                    alb = ElbApplicationLoadBalancer(label("Load balancer", "Application Load Balancer"), **node_attrs())
                    api = Fargate(label("API (SAML SP · SCIM)", "Amazon ECS on AWS Fargate"), **node_attrs())
                with Cluster("data", graph_attr={**GROUP["isolated"], **COLUMN, "label": cluster_label("Data layer")}):
                    db = Aurora(label("Identity & RBAC store", "Amazon Aurora PostgreSQL"), **node_attrs())
                with Cluster("sec", graph_attr={**GROUP["security"], **COLUMN, "label": cluster_label("Security & Observability")}):
                    sm = SecretsManager(label("Fernet key (SP key, TOTP)", "AWS Secrets Manager"), **node_attrs())
                    kms = KMS(label("Key encryption", "AWS KMS"), **node_attrs())
                    cw = Cloudwatch(label("Auth logs · alarms", "Amazon CloudWatch"), **node_attrs())
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11", fixedsize="false", height="0", width="0")

        users >> e("sync", "① open app — HTTPS") >> cf
        cf >> e("sync", "② /api/auth/saml/login") >> alb
        alb >> e("sync", "② forward") >> api
        api >> e("ext", "③ signed AuthnRequest (redirect via browser)", constraint=False) >> okta
        users >> e("ext", "④ sign in + MFA", constraint=False) >> okta
        okta >> e("ext", "⑤ signed assertion — HTTPS POST /api/auth/saml/acs (via browser)", minlen=2) >> waf
        waf >> e("mgmt", "Web ACL") >> cf
        api >> e("sync", "⑥ verify signature · InResponseTo · replay · audience → map groups → roles; create session") >> db
        sailpoint >> e("ext", "⑦ SCIM 2.0 Users/Groups — Bearer token (hashed at rest)", minlen=2) >> alb
        api >> e("sync", "⑧ group membership → roles; revoke sessions on change", constraint=False) >> db
        sm >> e("mgmt", "⑨ decrypt SP signing key", constraint=False) >> api
        kms >> e("mgmt", "envelope encryption", constraint=False) >> sm
        api >> e("mgmt", "auth success/failure logs", constraint=False) >> cw
        legend >> Edge(style="invis") >> cf
        db >> Edge(style="invis") >> sm  # Security & Observability column right of the data layer


def drawio(path: Path) -> None:
    d = Drawio(NAME, 1900, 1050)
    d.title(TITLE, SUBTITLE)
    d.dy = 50
    d.group("Identity providers", "external", 20, 60, 300, 860, "Outside AWS")
    d.group("AWS Cloud", "aws_cloud", 360, 60, 1500, 860)
    d.group("Edge", "layer", 390, 110, 240, 420)
    d.group("Region", "region", 660, 110, 1170, 780, "VPC · private subnets")
    d.group("Application layer", "private", 690, 170, 380, 420)
    d.group("Data layer", "isolated", 1100, 170, 340, 420)
    d.group("Security & Observability", "security", 690, 630, 1110, 230)
    d.group("Legend", "legend", 1470, 170, 330, 300)

    users = d.icon("Workforce users", "Browser", "users", "#232F3E", 140, 140, resource=False)
    okta = d.box("Authentication + MFA", "Okta (SAML 2.0 IdP)", 70, 400)
    sail = d.box("Identity governance", "SailPoint ISC / IIQ — SCIM 2.0 client", 70, 700, h=70)
    cf = d.icon("CDN", "Amazon CloudFront", "cloudfront", "#8C4FFF", 482, 180)
    waf = d.icon("Web ACL", "AWS WAF", "waf", "#DD344C", 482, 380)
    alb = d.icon("Load balancer", "Application Load Balancer", "application_load_balancer", "#8C4FFF", 760, 240, resource=False)
    api = d.icon("API (SAML SP · SCIM)", "Amazon ECS on AWS Fargate", "fargate", "#ED7100", 940, 420)
    db = d.icon("Users · roles · mappings · sessions · audit", "Amazon Aurora PostgreSQL", "aurora", "#C925D1", 1240, 300)
    sm = d.icon("Fernet key (SP key, TOTP)", "AWS Secrets Manager", "secrets_manager", "#DD344C", 800, 700)
    kms = d.icon("Key encryption", "AWS KMS", "key_management_service", "#DD344C", 1100, 700)
    cw = d.icon("Auth logs · alarms", "Amazon CloudWatch", "cloudwatch_2", "#E7157B", 1400, 700)
    d.text("<b>━━▶</b> synchronous<br><span style='color:#545B64'><b>━━▶</b></span> external system (via browser)<br>"
           "<span style='color:#7D8998'><b>┈┈▶</b></span> management / telemetry<br><br>①–⑨ numbered flows — see identity flow walkthrough",
           1485, 210, 300, 200, font=BRAND_BODY_FONT)

    E = d.edge
    E(users, cf, "① open app — HTTPS")
    E(cf, alb, "② /api/auth/saml/login")
    E(alb, api, "② forward")
    E(api, okta, "③ signed AuthnRequest (redirect via browser)", "ext")
    E(users, okta, "④ sign in + MFA", "ext")
    E(okta, waf, "⑤ signed assertion → POST /api/auth/saml/acs (via browser)", "ext")
    E(waf, cf, "Web ACL", "mgmt")
    E(api, db, "⑥ verify signature · InResponseTo · replay → map groups → roles; session")
    E(sail, alb, "⑦ SCIM 2.0 Users/Groups — Bearer token", "ext")
    E(api, db, "⑧ membership → roles; revoke sessions on change")
    E(sm, api, "⑨ decrypt SP signing key", "mgmt")
    E(kms, sm, "envelope encryption", "mgmt")
    E(api, cw, "auth logs", "mgmt")
    d.write(path)

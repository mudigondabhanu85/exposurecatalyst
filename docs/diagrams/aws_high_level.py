"""High-level AWS architecture — ExposureCatalyst production reference deployment (single region, Multi-AZ).

Rendered by docs/diagrams/_render_all.py into docs/assets/diagrams/aws_high_level.{svg,png,drawio}.
Flow numbers ①–⑮ match the walkthrough in docs/architecture/high-level.md.
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
from diagrams.aws.compute import ElasticContainerServiceService, Fargate
from diagrams.aws.database import Aurora, ElasticacheForRedis
from diagrams.aws.devtools import XRay
from diagrams.aws.engagement import SimpleEmailServiceSes
from diagrams.aws.general import InternetAlt1, Users
from diagrams.aws.integration import Eventbridge, SimpleQueueServiceSqs
from diagrams.aws.management import Cloudtrail, Cloudwatch, CloudwatchEventTimeBased
from diagrams.aws.ml import Bedrock
from diagrams.aws.network import CloudFront, ElbApplicationLoadBalancer, Endpoint, NATGateway, NetworkFirewall, Route53
from diagrams.aws.security import CertificateManager, Guardduty, IAMRole, KMS, SecretsManager, SecurityHub, WAF
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.saas.identity import Okta

NAME = "aws_high_level"
TITLE = "ExposureCatalyst — AWS Reference Architecture"
SUBTITLE = "Production deployment · single region · Multi-AZ · v0.4"


def e(kind: str, text: str, constraint: bool = True, minlen: int = 1) -> Edge:
    attrs = dict(EDGE[kind])
    if not constraint:
        attrs["constraint"] = "false"
    if minlen > 1:
        attrs["minlen"] = str(minlen)  # keeps external systems in the far-left column
    return Edge(xlabel=edge_label(text), **attrs)


INVIS = {"style": "invis"}


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE)}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR",
                 graph_attr=attrs, node_attr={"fontname": "Helvetica"}):
        # ---- External: left side (inbound) -------------------------------------------------
        with Cluster("users", graph_attr={**COLUMN, **GROUP["external"], "label": cluster_label("Users & Identity", "Outside AWS")}):
            users = Users(label("Analysts · Approvers · Admins", "Corporate browser"), **node_attrs())
            okta = Okta(label("Identity provider", "Okta (SAML 2.0 / OIDC)"), **node_attrs())
            sailpoint = InternetAlt1(label("Identity governance", "SailPoint ISC / IIQ (SCIM 2.0)"), **node_attrs())
        with Cluster("sources", graph_attr={**COLUMN, **GROUP["external"], "label": cluster_label("External Sources", "Systems of record")}):
            cve_src = InternetAlt1(label("CVE & exploit intel", "NVD · CISA KEV · FIRST EPSS · OSV · PSIRTs"), **node_attrs())
            tools = InternetAlt1(label("Security / CTEM tools", "Qualys · Tanium · Wiz · Zafran · ArmorCode · ServiceNow"), **node_attrs())
            news = InternetAlt1(label("News feeds", "CISA · vendor threat intel · security press"), **node_attrs())

        with Cluster("aws", graph_attr={**GROUP["aws_cloud"], "label": cluster_label("AWS Cloud")}):
            with Cluster("edge", graph_attr={**COLUMN, **GROUP["layer"], "label": cluster_label("Edge (global)")}):
                r53 = Route53(label("DNS", "Amazon Route 53"), **node_attrs())
                cf = CloudFront(label("CDN", "Amazon CloudFront"), **node_attrs())
                waf = WAF(label("Web ACL", "AWS WAF"), **node_attrs())
                acm = CertificateManager(label("TLS certificates", "AWS Certificate Manager"), **node_attrs())
                spa = SimpleStorageServiceS3Bucket(label("React SPA", "Amazon S3 (static, OAC)"), **node_attrs())

            with Cluster("region", graph_attr={**GROUP["region"], "label": cluster_label("Region  us-east-1", "2+ Availability Zones")}):
                with Cluster("secobs", graph_attr={**GROUP["security"], "label": cluster_label("Security & Observability")}):
                    secrets = SecretsManager(label("Credentials", "AWS Secrets Manager"), **node_attrs())
                    kms = KMS(label("Encryption keys", "AWS KMS (CMKs)"), **node_attrs())
                    iam = IAMRole(label("Task roles", "AWS IAM (least privilege)"), **node_attrs())
                    cw = Cloudwatch(label("Logs · metrics · alarms", "Amazon CloudWatch"), **node_attrs())
                    xray = XRay(label("Tracing", "AWS X-Ray"), **node_attrs())
                    trail = Cloudtrail(label("API audit", "AWS CloudTrail"), **node_attrs())
                    gd = Guardduty(label("Threat detection", "Amazon GuardDuty"), **node_attrs())
                    sh = SecurityHub(label("Posture", "AWS Security Hub"), **node_attrs())

                with Cluster("vpc", graph_attr={**GROUP["vpc"], "label": cluster_label("VPC  10.20.0.0/16")}):
                    with Cluster("public", graph_attr={**COLUMN, **GROUP["public"], "label": cluster_label("Public subnets", "AZ-a · AZ-b")}):
                        alb = ElbApplicationLoadBalancer(label("Load balancer", "Application Load Balancer"), **node_attrs())
                        nfw = NetworkFirewall(label("Egress filter", "AWS Network Firewall"), **node_attrs())
                        nat = NATGateway(label("Egress", "NAT gateway (per AZ)"), **node_attrs())
                    with Cluster("private", graph_attr={**COLUMN, **GROUP["private"], "label": cluster_label("Private app subnets", "AZ-a · AZ-b — Application / Logic layer")}):
                        api = Fargate(label("API", "Amazon ECS on AWS Fargate"), **node_attrs())
                        worker = ElasticContainerServiceService(label("Worker", "Amazon ECS on AWS Fargate"), **node_attrs())
                        sched = ElasticContainerServiceService(label("Scheduler", "Amazon ECS on AWS Fargate"), **node_attrs())
                        vpce = Endpoint(label("Private AWS access", "VPC endpoints (S3 · Secrets Manager · KMS · SQS)"), **node_attrs())
                    with Cluster("isolated", graph_attr={**COLUMN, **GROUP["isolated"], "label": cluster_label("Isolated data subnets", "AZ-a · AZ-b — no internet route")}):
                        aurora = Aurora(label("Primary database", "Amazon Aurora PostgreSQL (Multi-AZ)"), **node_attrs())
                        redis = ElasticacheForRedis(label("Cache / queue", "Amazon ElastiCache for Redis"), **node_attrs())

                with Cluster("messaging", graph_attr={**COLUMN, **GROUP["layer"], "label": cluster_label("Messaging")}):
                    ebs = CloudwatchEventTimeBased(label("Scheduler (alt.)", "Amazon EventBridge Scheduler"), **node_attrs())
                    sqs = SimpleQueueServiceSqs(label("Job queues", "Amazon SQS (ingest · correlate · email)"), **node_attrs())
                    bus = Eventbridge(label("Domain events", "Amazon EventBridge event bus"), **node_attrs())
                with Cluster("data", graph_attr={**COLUMN, **GROUP["layer"], "label": cluster_label("Data layer")}):
                    s3 = SimpleStorageServiceS3Bucket(label("Exports & archives", "Amazon S3 (SSE-KMS, versioned)"), **node_attrs())
                with Cluster("managed", graph_attr={**COLUMN, **GROUP["layer"], "label": cluster_label("Managed AI & email")}):
                    bedrock = Bedrock(label("LLM (optional)", "Amazon Bedrock"), **node_attrs())
                    ses = SimpleEmailServiceSes(label("Email", "Amazon SES"), **node_attrs())
        with Cluster("outbound", graph_attr={**COLUMN, **GROUP["external"], "label": cluster_label("Outbound Services", "Outside AWS")}):
            smtp = InternetAlt1(label("Mail relay (alt.)", "Microsoft 365 / corporate SMTP"), **node_attrs())
            ai_ext = InternetAlt1(label("External AI vendors", "Allowlisted providers only"), **node_attrs())

        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname="Helvetica", fontsize="11", fixedsize="false", height="0", width="0")

        # ---- Flows -------------------------------------------------------------------------------
        users >> e("sync", "① DNS lookup") >> r53
        users >> e("sync", "② HTTPS (TLS 1.2+) — SPA & /api") >> cf
        users >> e("ext", "SSO sign-in + MFA", constraint=False) >> okta
        okta >> e("ext", "③ SAML assertion — HTTPS POST /saml/acs", minlen=2) >> alb
        sailpoint >> e("ext", "SCIM 2.0 — users & groups → roles", minlen=2) >> alb
        waf >> e("mgmt", "Web ACL (OWASP, rate limits)") >> cf
        acm >> e("mgmt", "TLS cert") >> cf
        cf >> e("sync", "static assets (OAC)") >> spa
        cf >> e("sync", "④ /api/* origin — HTTPS") >> alb
        alb >> e("sync", "⑤ HTTPS → target group") >> api
        api >> e("sync", "⑥ SQL / TLS") >> aurora
        api >> e("sync", "cache · rate limits (TLS)") >> redis
        api >> e("async", "⑦ enqueue job — SQS") >> sqs
        sched >> e("async", "⑧ hourly tick — due sources") >> sqs
        ebs >> e("async", "⑧ rate(1 hour) — alt. trigger") >> sqs
        sqs >> e("async", "⑨ long-poll jobs") >> worker
        cve_src >> e("egress", "⑩ Hourly fetch — NVD API 2.0 · KEV · EPSS", minlen=2) >> nfw
        tools >> e("egress", "⑪ Asset query — Qualys / Tanium / Wiz APIs", minlen=2) >> nfw
        news >> e("egress", "RSS / HTTPS — news", minlen=2) >> nfw
        nfw >> e("egress", "domain allowlist") >> nat
        nat >> e("egress", "egress-initiated HTTPS") >> worker
        worker >> e("sync", "⑫ upsert CVEs / assets — SQL/TLS") >> aurora
        worker >> e("async", "⑬ CVE.New · CVE.KEVAdded · Advisory.Sent · Alert.Triggered") >> bus
        worker >> e("sync", "Excel exports · email archive — SSE-KMS") >> s3
        worker >> e("sync", "⑭ SMTP/TLS — advisory email") >> ses
        worker >> e("egress", "⑭ SMTP/TLS 587 — advisory email (alt.)") >> smtp
        worker >> e("sync", "⑮ InvokeModel — redacted prompt") >> bedrock
        worker >> e("egress", "⑮ HTTPS — redacted prompt") >> ai_ext
        [api, worker] >> e("sync", "PrivateLink — no internet path", constraint=False) >> vpce
        vpce >> e("sync", "GetSecretValue", constraint=False) >> secrets
        secrets >> e("mgmt", "envelope encryption") >> kms
        iam >> e("mgmt", "task role credentials") >> api
        [api, worker] >> e("mgmt", "logs · metrics") >> cw
        [api, worker] >> e("mgmt", "traces") >> xray
        trail >> e("mgmt", "API audit events") >> cw
        gd >> e("mgmt", "findings") >> sh

        # ---- Layout skeleton (invisible): Security & Observability as two rows under the VPC ----
        legend >> Edge(**INVIS) >> r53
        r53 >> Edge(**INVIS) >> secrets >> Edge(**INVIS) >> kms >> Edge(**INVIS) >> iam >> Edge(**INVIS) >> trail
        r53 >> Edge(**INVIS) >> cw >> Edge(**INVIS) >> xray >> Edge(**INVIS) >> gd >> Edge(**INVIS) >> sh
        worker >> Edge(**INVIS) >> s3
        aurora >> Edge(**INVIS) >> ses


def drawio(path: Path) -> None:
    d = Drawio(NAME, 2440, 1600)
    d.title(TITLE, SUBTITLE)
    d.dy = 50

    # boundaries (drawn first so they sit behind icons)
    d.group("Users & Identity", "external", 20, 60, 300, 560, "Outside AWS")
    d.group("External Sources", "external", 20, 650, 300, 560, "Systems of record")
    d.group("AWS Cloud", "aws_cloud", 350, 60, 1710, 1470)
    d.group("Edge (global)", "layer", 380, 110, 260, 950)
    d.group("Region  us-east-1", "region", 670, 110, 1370, 1400, "2+ Availability Zones")
    d.group("VPC  10.20.0.0/16", "vpc", 700, 170, 830, 880)
    d.group("Public subnets", "public", 720, 230, 230, 800, "AZ-a · AZ-b")
    d.group("Private app subnets", "private", 970, 230, 270, 800, "AZ-a · AZ-b — Application / Logic layer")
    d.group("Isolated data subnets", "isolated", 1260, 230, 250, 800, "AZ-a · AZ-b — no internet route")
    d.group("Messaging", "layer", 1560, 170, 460, 260)
    d.group("Data layer", "layer", 1560, 450, 460, 190)
    d.group("Managed AI & email", "layer", 1560, 660, 460, 190)
    d.group("Security & Observability", "security", 700, 1080, 1320, 410)
    d.group("Outbound Services", "external", 2090, 600, 320, 420, "Outside AWS")
    d.group("Legend", "legend", 2090, 1060, 320, 300)

    users = d.icon("Analysts · Approvers · Admins", "Corporate browser", "users", "#232F3E", 140, 130, resource=False)
    okta = d.box("Identity provider", "Okta — SAML 2.0 / OIDC", 70, 300)
    sail = d.box("Identity governance", "SailPoint ISC / IIQ — SCIM 2.0", 70, 470)
    cve = d.box("CVE & exploit intel", "NVD · CISA KEV · FIRST EPSS · OSV · PSIRTs", 70, 730)
    tools = d.box("Security / CTEM tools", "Qualys · Tanium · Wiz · Zafran · ArmorCode · ServiceNow CMDB", 70, 900, h=70)
    news = d.box("News feeds", "CISA · vendor threat intel · security press", 70, 1090)

    r53 = d.icon("DNS", "Amazon Route 53", "route_53", "#8C4FFF", 482, 170)
    cf = d.icon("CDN", "Amazon CloudFront", "cloudfront", "#8C4FFF", 482, 360)
    waf = d.icon("Web ACL", "AWS WAF", "waf", "#DD344C", 482, 550)
    acm = d.icon("TLS certificates", "AWS Certificate Manager", "certificate_manager_3", "#DD344C", 482, 740)
    spa = d.icon("React SPA", "Amazon S3 (static, OAC)", "s3", "#7AA116", 482, 920)

    alb = d.icon("Load balancer", "Application Load Balancer", "application_load_balancer", "#8C4FFF", 807, 300, resource=False)
    nfw = d.icon("Egress filter", "AWS Network Firewall", "network_firewall", "#8C4FFF", 807, 560)
    nat = d.icon("Egress", "NAT gateway (per AZ)", "nat_gateway", "#8C4FFF", 807, 820, resource=False)

    api = d.icon("API", "Amazon ECS on AWS Fargate", "fargate", "#ED7100", 1077, 300)
    worker = d.icon("Worker", "Amazon ECS on AWS Fargate", "fargate", "#ED7100", 1077, 520)
    sched = d.icon("Scheduler", "Amazon ECS on AWS Fargate", "fargate", "#ED7100", 1077, 720)
    vpce = d.icon("Private AWS access", "VPC endpoints (S3 · Secrets Manager · KMS · SQS)", "endpoints", "#8C4FFF", 1077, 900, resource=False)

    aurora = d.icon("Primary database", "Amazon Aurora PostgreSQL (Multi-AZ)", "aurora", "#C925D1", 1357, 300)
    redis = d.icon("Cache / queue", "Amazon ElastiCache for Redis", "elasticache", "#C925D1", 1357, 560)

    ebs = d.icon("Scheduler (alt.)", "Amazon EventBridge Scheduler", "eventbridge", "#E7157B", 1600, 230)
    sqs = d.icon("Job queues", "Amazon SQS (ingest · correlate · email)", "sqs", "#E7157B", 1760, 230)
    bus = d.icon("Domain events", "Amazon EventBridge event bus", "eventbridge", "#E7157B", 1920, 230)
    s3 = d.icon("Exports & archives", "Amazon S3 (SSE-KMS, versioned)", "s3", "#7AA116", 1760, 510)
    ses = d.icon("Email", "Amazon SES", "simple_email_service", "#DD344C", 1640, 720)
    bedrock = d.icon("LLM (optional)", "Amazon Bedrock", "bedrock", "#01A88D", 1880, 720)

    xs = [740, 900, 1060, 1220, 1380, 1540, 1700, 1860]
    sec = [("Credentials", "AWS Secrets Manager", "secrets_manager", "#DD344C"),
           ("Encryption keys", "AWS KMS (CMKs)", "key_management_service", "#DD344C"),
           ("Task roles", "AWS IAM (least privilege)", "identity_and_access_management", "#DD344C"),
           ("Logs · metrics · alarms", "Amazon CloudWatch", "cloudwatch_2", "#E7157B"),
           ("Tracing", "AWS X-Ray", "xray", "#ED7100"),
           ("API audit", "AWS CloudTrail", "cloudtrail", "#E7157B"),
           ("Threat detection", "Amazon GuardDuty", "guardduty", "#DD344C"),
           ("Posture", "AWS Security Hub", "security_hub", "#DD344C")]
    secrets, kms, iam, cw, xray, trail, gd, sh = (d.icon(r, s, i, c, x, 1160) for (r, s, i, c), x in zip(sec, xs, strict=True))

    smtp = d.box("Mail relay (alt.)", "Microsoft 365 / corporate SMTP", 2150, 680)
    ai_ext = d.box("External AI vendors", "Allowlisted providers only", 2150, 860)
    d.text("<b>━━▶</b> synchronous (HTTPS / SQL-TLS)<br><span style='color:#E7157B'><b>╍╍▶</b></span> async message / event<br>"
           "<span style='color:#DD344C'><b>━━▶</b></span> egress via NAT + Network Firewall<br>"
           "<span style='color:#545B64'><b>━━▶</b></span> external system<br><span style='color:#7D8998'><b>┈┈▶</b></span> management / telemetry<br>"
           "<br>①–⑮ numbered flows — see architecture walkthrough", 2105, 1100, 290, 220,
           font=BRAND_BODY_FONT)

    E = d.edge
    E(users, r53, "① DNS lookup")
    E(users, cf, "② HTTPS (TLS 1.2+) — SPA & /api")
    E(users, okta, "SSO sign-in + MFA", "ext")
    E(okta, alb, "③ SAML assertion — HTTPS POST /saml/acs", "ext")
    E(sail, alb, "SCIM 2.0 — users & groups → roles", "ext")
    E(waf, cf, "Web ACL", "mgmt")
    E(acm, cf, "TLS cert", "mgmt")
    E(cf, spa, "static assets (OAC)")
    E(cf, alb, "④ /api/* origin — HTTPS")
    E(alb, api, "⑤ HTTPS → target group")
    E(api, aurora, "⑥ SQL / TLS")
    E(api, redis, "cache · rate limits")
    E(api, sqs, "⑦ enqueue job", "async")
    E(sched, sqs, "⑧ hourly tick", "async")
    E(ebs, sqs, "⑧ alt. trigger", "async")
    E(sqs, worker, "⑨ long-poll jobs", "async")
    E(cve, nfw, "⑩ Hourly fetch — NVD API 2.0 · KEV · EPSS", "egress")
    E(tools, nfw, "⑪ Asset query — Qualys / Tanium / Wiz APIs", "egress")
    E(news, nfw, "RSS / HTTPS — news", "egress")
    E(nfw, nat, "domain allowlist", "egress")
    E(nat, worker, "egress-initiated HTTPS", "egress")
    E(worker, aurora, "⑫ upsert CVEs / assets — SQL/TLS")
    E(worker, bus, "⑬ CVE.New · CVE.KEVAdded · Advisory.Sent · Alert.Triggered", "async")
    E(worker, s3, "exports · archive (SSE-KMS)")
    E(worker, ses, "⑭ SMTP/TLS — advisory email")
    E(worker, smtp, "⑭ SMTP/TLS 587 (alt.)", "egress")
    E(worker, bedrock, "⑮ InvokeModel — redacted prompt")
    E(worker, ai_ext, "⑮ HTTPS — redacted prompt", "egress")
    E(api, vpce, "PrivateLink")
    E(worker, vpce, "PrivateLink")
    E(vpce, secrets, "GetSecretValue")
    E(secrets, kms, "envelope encryption", "mgmt")
    E(iam, api, "task role", "mgmt")
    E(worker, cw, "logs · metrics", "mgmt")
    E(worker, xray, "traces", "mgmt")
    E(trail, cw, "API audit events", "mgmt")
    E(gd, sh, "findings", "mgmt")
    d.write(path)

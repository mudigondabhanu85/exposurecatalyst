"""Docker deployment: containers, networks, volumes and start order (docker compose up)."""

from __future__ import annotations

from pathlib import Path

from _aws_style import (BRAND_BODY_FONT, COLUMN, DIAGRAM_ATTRS, GROUP, cluster_label, flow, label, legend_html,
                        node_attrs, title_block)
from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.general import Users
from diagrams.generic.storage import Storage
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.network import Caddy, Internet
from diagrams.programming.framework import Fastapi
from diagrams.programming.language import Python

AUTO_DRAWIO = True
NAME = "container_topology"
TITLE = "ExposureCatalyst — Docker Container Topology"
SUBTITLE = "docker compose up -d · only the proxy publishes ports · init → postgres → migrate → api → scheduler → proxy"


def build(out_dir: Path, fmt: str, dpi: int) -> None:
    attrs = {**DIAGRAM_ATTRS, "dpi": str(dpi), "label": title_block(TITLE, SUBTITLE), "ranksep": "1.1"}
    with Diagram(TITLE, filename=str(out_dir / NAME), outformat=fmt, show=False, direction="LR", graph_attr=attrs):
        users = Users(label("Users / IdP", "https://<fqdn> · 80 → 443"), **node_attrs())
        with Cluster("host", graph_attr={**GROUP["aws_cloud"], "label": cluster_label("Docker host", "Compose v2.24+")}):
            with Cluster("edge", graph_attr={**GROUP["public"], **COLUMN,
                                             "label": cluster_label("edge network", "published 80/443 only")}):
                proxy = Caddy(label("proxy", "Caddy · TLS 1.2/1.3 · HTTP→HTTPS · SPA assets"), **node_attrs())
            with Cluster("app", graph_attr={**GROUP["private"], **COLUMN, "label": cluster_label("application")}):
                api = Fastapi(label("api", "FastAPI · uvicorn workers · non-root, read-only"), **node_attrs())
                sched = Python(label("scheduler", "ingestion · alerts · cert & licence reminders"), **node_attrs())
                worker = Python(label("worker (profile scale)", "extra job runners · DB claim"), **node_attrs())
            with Cluster("oneshot", graph_attr={**GROUP["layer"], **COLUMN,
                                                "label": cluster_label("one-shot", "run before the app")}):
                init = Python(label("init", "secrets + self-signed cert (never overwrites)"), **node_attrs())
                migrate = Python(label("migrate", "Alembic → head"), **node_attrs())
            with Cluster("backend", graph_attr={**GROUP["isolated"], **COLUMN,
                                                "label": cluster_label("backend network", "internal: no egress")}):
                db = PostgreSQL(label("postgres", "16 · pgdata (or external DB)"), **node_attrs())
                redis = Redis(label("redis (profile scale)", "password from db-secret"), **node_attrs())
                backup = Python(label("backup (profile backup)", "pg_dump → backups"), **node_attrs())
            with Cluster("vols", graph_attr={**GROUP["layer"], **COLUMN, "label": cluster_label("named volumes")}):
                secrets = Storage(label("secrets · db-secret", "Fernet key · DB/Redis passwords"), **node_attrs())
                certs = Storage(label("certs", "active · previous · trusted-ca · proxy config"), **node_attrs())
                admin_sock = Storage(label("caddy-admin", "admin API unix socket"), **node_attrs())
        internet = Internet(label("Internet / corporate proxy", "CVE sources · tools · AI · intel"), **node_attrs())
        with Cluster("legend", graph_attr={**GROUP["legend"], "label": ""}):
            legend = Node(legend_html(), shape="plaintext", fontname=BRAND_BODY_FONT, fontsize="11",
                          fixedsize="false", height="0", width="0")

        users >> flow("sync", "HTTPS") >> proxy
        proxy >> flow("sync", "/api · /docs · /saml · /scim") >> api
        init >> flow("mgmt", "① generate") >> secrets
        init >> flow("mgmt", "self-signed cert", constraint=False) >> certs
        migrate >> flow("mgmt", "② schema") >> db
        api >> flow("sync", "SQL") >> db
        sched >> flow("sync", "SQL", constraint=False) >> db
        worker >> flow("sync", "SQL", constraint=False) >> db
        backup >> flow("async", "nightly", constraint=False) >> db
        api >> flow("mgmt", "install / rollback cert") >> certs
        certs >> flow("mgmt", "files (read-only)", constraint=False) >> proxy
        api >> flow("mgmt", "hot reload", constraint=False) >> admin_sock
        admin_sock >> flow("mgmt", "POST /load", constraint=False) >> proxy
        api >> flow("egress", "https (allowlist)") >> internet
        sched >> flow("egress", "https", constraint=False) >> internet
        worker >> Edge(style="invis") >> redis
        legend >> Edge(style="invis") >> users

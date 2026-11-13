# Renders docs/diagrams/*.py (mingrammer "diagrams" + Graphviz). Used by `make diagrams` / CI.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends graphviz fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "diagrams==0.24.4"
RUN useradd -m render
USER render

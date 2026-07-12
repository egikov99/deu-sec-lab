FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    golang-go \
    nmap \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/usr/local/bin
ARG CLAUDE_BUGHUNTER_REPO=""
ARG CLAUDE_BUGHUNTER_REF="main"

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

RUN mkdir -p /opt/methodology && \
    if [ -n "$CLAUDE_BUGHUNTER_REPO" ]; then \
      git clone --depth 1 --branch "$CLAUDE_BUGHUNTER_REF" "$CLAUDE_BUGHUNTER_REPO" /opt/methodology/Claude-BugHunter; \
    fi

RUN groupadd --system --gid 10001 worker && \
    useradd --system --uid 10001 --gid worker --home-dir /home/worker --create-home worker && \
    mkdir -p /home/worker/.config/nuclei /home/worker/.cache/nuclei /home/worker/.local/share/nuclei/templates /reports && \
    chown -R worker:worker /home/worker /reports /opt/methodology

ENV HOME=/home/worker
ENV XDG_CONFIG_HOME=/home/worker/.config
ENV XDG_CACHE_HOME=/home/worker/.cache
ENV NUCLEI_CONFIG_DIR=/home/worker/.config/nuclei
ENV NUCLEI_CACHE_DIR=/home/worker/.cache/nuclei
ENV NUCLEI_TEMPLATES_DIR=/home/worker/.local/share/nuclei/templates

WORKDIR /app
COPY worker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared ./shared
COPY worker/app ./app
COPY --chmod=755 worker/entrypoint.sh /entrypoint.sh
ENV PYTHONPATH=/app

RUN chown -R worker:worker /app

USER worker
RUN nuclei -update-templates && nuclei -validate -t "${NUCLEI_TEMPLATES_DIR}"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-u", "app/worker.py"]

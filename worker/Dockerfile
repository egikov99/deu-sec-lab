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

ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"
ARG CLAUDE_BUGHUNTER_REPO=""
ARG CLAUDE_BUGHUNTER_REF="main"

RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    nuclei -update-templates || true

RUN mkdir -p /opt/methodology && \
    if [ -n "$CLAUDE_BUGHUNTER_REPO" ]; then \
      git clone --depth 1 --branch "$CLAUDE_BUGHUNTER_REF" "$CLAUDE_BUGHUNTER_REPO" /opt/methodology/Claude-BugHunter || true; \
    fi

WORKDIR /app
COPY worker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared ./shared
COPY worker/app ./app
ENV PYTHONPATH=/app

CMD ["python", "-u", "app/worker.py"]

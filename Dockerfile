FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash git curl wget unzip ca-certificates gnupg \
    python3 python3-pip pipx \
    nodejs npm golang-go \
    nmap jq whois dnsutils \
    sqlmap amass \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @openai/codex

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/epi052/feroxbuster@latest || true

RUN git clone --depth=1 https://github.com/elementalsouls/Claude-BugHunter.git /opt/Claude-BugHunter && \
    cd /opt/Claude-BugHunter && \
    bash scripts/install.sh --all || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]

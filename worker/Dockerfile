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
ARG CLAUDE_BUGHUNTER_COMMIT
ARG CLAUDE_BUGHUNTER_REPOSITORY="https://github.com/elementalsouls/Claude-BugHunter.git"

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

RUN test -n "$CLAUDE_BUGHUNTER_COMMIT" && \
    export CLAUDE_BUGHUNTER_COMMIT CLAUDE_BUGHUNTER_REPOSITORY && \
    mkdir -p /opt/methodology && \
    git clone "$CLAUDE_BUGHUNTER_REPOSITORY" /opt/methodology/Claude-BugHunter && \
    git -C /opt/methodology/Claude-BugHunter checkout "$CLAUDE_BUGHUNTER_COMMIT" && \
    export ACTUAL_COMMIT="$(git -C /opt/methodology/Claude-BugHunter rev-parse HEAD)" && \
    test "$ACTUAL_COMMIT" = "$CLAUDE_BUGHUNTER_COMMIT" && \
    test -f /opt/methodology/Claude-BugHunter/README.md && \
    export SKILL_COUNT="$(find /opt/methodology/Claude-BugHunter -name SKILL.md -type f | wc -l)" && \
    test "$SKILL_COUNT" -gt 0 && \
    export COMMAND_COUNT="$(find /opt/methodology/Claude-BugHunter -path '*/commands/*' -type f \( -name '*.md' -o -name '*.json' -o -name '*.yaml' -o -name '*.yml' \) | wc -l)" && \
    export SOURCE_HASHES="$(find /opt/methodology/Claude-BugHunter -type f \( -name 'SKILL.md' -o -path '*/commands/*' -o -name '*.md' -o -name '*.json' -o -name '*.yaml' -o -name '*.yml' \) -print | sort | head -n 200 | xargs sha256sum)" && \
    python -c 'import json, os, pathlib; root=pathlib.Path("/opt/methodology/Claude-BugHunter"); hashes={}; raw=os.environ["SOURCE_HASHES"].splitlines(); [hashes.setdefault(line.split(maxsplit=1)[1].replace(str(root)+"/",""), line.split(maxsplit=1)[0]) for line in raw if line.strip()]; json.dump({"repository": os.environ["CLAUDE_BUGHUNTER_REPOSITORY"], "requested_commit": os.environ["CLAUDE_BUGHUNTER_COMMIT"], "actual_commit": os.environ["ACTUAL_COMMIT"], "build_timestamp": os.popen("date -u +%Y-%m-%dT%H:%M:%SZ").read().strip(), "skill_count": int(os.environ["SKILL_COUNT"]), "command_count": int(os.environ["COMMAND_COUNT"]), "source_file_hashes": hashes}, open(root/"manifest.json","w"), indent=2)'

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
ENV CLAUDE_BUGHUNTER_ROOT=/opt/methodology/Claude-BugHunter

WORKDIR /app
COPY worker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# Install last: Python's transitive httpx package also owns /usr/local/bin/httpx.
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    httpx -version 2>&1 | grep -Eiq 'projectdiscovery|current version' && \
    go version -m "$(command -v httpx)" | grep -Fq 'github.com/projectdiscovery/httpx/cmd/httpx' && \
    httpx -h 2>&1 | grep -Eq -- '-silent' && \
    httpx -h 2>&1 | grep -Eq -- '-json' && \
    httpx -h 2>&1 | grep -Eq -- '-status-code' && \
    httpx -h 2>&1 | grep -Eq -- '-title' && \
    httpx -h 2>&1 | grep -Eq -- '-tech-detect' && \
    httpx -h 2>&1 | grep -Eq -- '-follow-redirects' && \
    httpx -h 2>&1 | grep -Eq -- '-timeout' && \
    httpx -h 2>&1 | grep -Eq -- '-retries'
COPY shared ./shared
COPY worker/app ./app
COPY --chmod=755 worker/entrypoint.sh /entrypoint.sh
ENV PYTHONPATH=/app

RUN chown -R worker:worker /app

USER worker
RUN nuclei -update-templates && nuclei -validate -t "${NUCLEI_TEMPLATES_DIR}"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-u", "app/worker.py"]

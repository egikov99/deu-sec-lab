# DEU Security Lab

Internal web panel for authorized security checks of projects you own or are allowed to test.

The MVP is intentionally small:

- `web`: Next.js, TypeScript, TailwindCSS UI.
- `api`: FastAPI REST API.
- `worker`: Python RQ worker that runs only whitelisted security tools.
- `redis`: scan queue.
- `reports/{project_id}/{scan_id}`: generated scan artifacts.

No multi-tenant SaaS, billing, marketplace, RBAC, Kubernetes, host scanning, or automatic aggressive testing is included in this stage.

## User Flow

1. Open the web panel.
2. Create a project with name, target URL/domain/IP, description, scan type, and optional origin IP authorization.
3. Open the project details page.
4. Click `Проверить безопасность`.
5. Watch status, progress, current step, and logs.
6. Review summary, findings, recommendations, technical details, raw output, and report files.

## Scan Pipeline

Basic scan:

1. Validate target.
2. `httpx`
3. `katana`
4. `nuclei` with intrusive/dos/bruteforce/fuzz/headless tags excluded.
5. Generate report.

Extended scan:

1. `subfinder` for domains.
2. `dnsx`
3. `httpx`
4. `katana`
5. `nuclei`
6. `nmap` on allowed ports only.
7. Generate report.

`sqlmap` is not launched automatically in the MVP.

## Safety Controls

- The UI never sends shell commands or arbitrary tool arguments.
- Worker commands are built from a fixed whitelist: `httpx`, `katana`, `nuclei`, `subfinder`, `dnsx`, `nmap`.
- Targets are normalized and validated server-side.
- Private, local, loopback, link-local, and multicast targets are blocked unless `ALLOW_PRIVATE_TARGETS=true`.
- Nmap results against Cloudflare/CDN infrastructure are marked as public edge exposure and are not attributed to the origin server.
- Origin infrastructure scans run only when an origin IP is explicitly configured and authorization is confirmed.
- Nuclei templates are initialized under the worker user's persistent data directory and validated before scans.

## Reports

Each completed scan writes files to:

```text
/reports/{project_id}/{scan_id}/
```

Generated files:

- `summary.md`
- `report.html`
- `raw.json`
- `normalized.json`
- `metadata.json`
- `findings.json`
- `logs.txt`
- `report.pdf` when PDF generation succeeds

## Claude-BugHunter Methodology

The worker image has a reserved methodology directory at `/opt/methodology`.
For every scan, the worker records the selected workflow, checklist, methodology files, version/commit when available, and used skills in scan metadata. Claude Code and slash commands are not used.

To include the tested Claude-BugHunter repository in published worker images, set GitHub Actions repository variables:

- `CLAUDE_BUGHUNTER_REPO`: repository URL
- `CLAUDE_BUGHUNTER_REF`: branch, tag, or commit, defaults to `main`

The MVP does not require Claude Code or slash commands.

## Portainer Deployment

1. Copy `.env.example` to `.env` and adjust values.
2. In Portainer, go to `Stacks -> Add stack`.
3. Use this repository and `docker-compose.yml`.
4. Deploy.
5. Open `http://SERVER_IP:3000`.

The compose file uses published GHCR images:

- `ghcr.io/egikov99/deu-sec-lab-web:latest`
- `ghcr.io/egikov99/deu-sec-lab-api:latest`
- `ghcr.io/egikov99/deu-sec-lab-worker:latest`

Persistent volumes:

- `reports-data`: report artifacts
- `postgres-data`: database
- `redis-data`: queue data
- `nuclei-data`: Nuclei templates under `/home/worker/.local/share/nuclei`
- `nuclei-cache`: Nuclei cache under `/home/worker/.cache/nuclei`

## Environment

```env
INTERNAL_API_URL=http://api:8000
REDIS_URL=redis://redis:6379/0
DATABASE_URL=sqlite:////data/app.db
REPORTS_ROOT=/reports
ALLOW_PRIVATE_TARGETS=false
NMAP_ALLOWED_PORTS=80,443,8080,8443
NUCLEI_CONFIG_DIR=/home/worker/.config/nuclei
NUCLEI_CACHE_DIR=/home/worker/.cache/nuclei
NUCLEI_TEMPLATES_DIR=/home/worker/.local/share/nuclei/templates
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
```

If `OPENAI_API_KEY` is empty, reports are still generated without AI.

The browser uses same-origin `/api/*` requests. Do not set `NEXT_PUBLIC_API_URL` to `http://api:8000`; the `api` hostname is only resolvable inside Docker and is used by the Next.js server-side rewrite through `INTERNAL_API_URL`.

## GitHub Actions

`.github/workflows/docker-publish.yml` builds and publishes the three runtime images to GHCR on pushes to `main` and manual dispatch.

## Important

Use this tool only for systems you own or have written authorization to test. Do not expose the panel publicly without an additional access-control layer.

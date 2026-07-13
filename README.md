# DEU Security Lab

Internal web panel for authorized security checks of projects you own or are allowed to test.

The platform is centered on Claude-BugHunter as the scan orchestration engine:

- `web`: Next.js, TypeScript, TailwindCSS UI.
- `api`: FastAPI REST API.
- `worker`: Python RQ worker that runs the `ClaudeBugHunterAgentRunner` with a strict tool registry.
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

## Claude-BugHunter Agent Engine

Scans are no longer a fixed `subfinder -> httpx -> katana -> nuclei` sequence. The worker:

1. Loads `/opt/methodology/Claude-BugHunter`.
2. Indexes `skills/*/SKILL.md`, commands, workflows, report templates, vulnerability patterns, chain templates, and validation guidance when present.
3. Selects relevant skills for the project and scan mode.
4. Creates a structured JSON scan plan.
5. Lets OpenAI refine planner/analyzer/reporter JSON when `OPENAI_API_KEY` is configured.
6. Executes only registered tool calls with Pydantic argument schemas.
7. Saves every step, artifact, AI operational summary, validation decision, finding, and report.

If OpenAI is not configured, the runner still uses the indexed Claude-BugHunter methodology and a deterministic safe plan.

## Safety Controls

- The UI never sends shell commands or arbitrary tool arguments.
- Worker commands are built from a fixed registry: `subfinder`, `dnsx`, `httpx`, `katana`, `nuclei`, `nmap`, `ffuf`, `feroxbuster`, `http_request`, `openapi_parser`, `js_endpoint_extractor`, and `header_tls_checker`.
- LLM output is accepted only as structured JSON. Arbitrary shell commands, `shell=True`, destructive payloads, DoS, brute force, data modification, persistence, and lateral movement are blocked.
- Validation modes are `passive`, `safe_validation`, and `explicit_approval`; safe validation is the default.
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

Generated files include:

- `summary.md`
- `report.md`
- `report.html`
- `raw.json`
- `normalized.json`
- `metadata.json`
- `methodology.json`
- `findings.json`
- `scan-plan.json`
- `timeline.json`
- `logs.txt`
- `full-scan.zip`
- `report.pdf` when PDF generation succeeds

## Claude-BugHunter Methodology

The worker image clones Claude-BugHunter into `/opt/methodology/Claude-BugHunter`.
For every scan, the worker records the repository, commit SHA, selected skills, selected workflows, generated checklist, completed/skipped checklist items, agent iterations, model, token usage, tool calls, and validation decisions. Claude Code and slash commands are not used.

The worker build pins the SecOps-approved methodology commit and fails if the commit is missing or cannot be checked out:

- `CLAUDE_BUGHUNTER_COMMIT=05098fc78842ec23fb96be4d07bd9cdc128a443b`
- `CLAUDE_BUGHUNTER_REPOSITORY=https://github.com/elementalsouls/Claude-BugHunter.git`

The build writes `/opt/methodology/Claude-BugHunter/manifest.json`. The readiness endpoint `/api/readiness` reports whether the repository exists, the resolved commit SHA, manifest status, indexed methodology sections, and whether the runtime is ready.

## Portainer Deployment

1. Copy `.env.example` to `.env` and adjust values.
2. In Portainer, go to `Stacks -> Add stack`.
3. Use this repository and `docker-compose.yml`.
4. Deploy.
5. Open `http://SERVER_IP:3000`.

The compose file uses published GHCR images:

- `ghcr.io/egikov99/deu-sec-lab-web:latest`
- `ghcr.io/egikov99/deu-sec-lab-api:latest`
- `ghcr.io/egikov99/deu-sec-lab-worker:${WORKER_IMAGE_TAG}`

Set `WORKER_IMAGE_TAG` to the immutable GitHub SHA tag printed by the Docker publish workflow.

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
WORKER_IMAGE_TAG=<github-sha-from-docker-publish-workflow>
```

If `OPENAI_API_KEY` is empty, reports are still generated without AI.

The browser uses same-origin `/api/*` requests. Do not set `NEXT_PUBLIC_API_URL` to `http://api:8000`; the `api` hostname is only resolvable inside Docker and is used by the Next.js server-side rewrite through `INTERNAL_API_URL`.

## GitHub Actions

`.github/workflows/docker-publish.yml` builds and publishes the three runtime images to GHCR on pushes to `main` and manual dispatch. The worker image is built locally first, smoke-tested for `CLAUDE_BUGHUNTER_ROOT`, `manifest.json`, checked-out commit, and at least one `SKILL.md`, then published as both `ghcr.io/egikov99/deu-sec-lab-worker:${GITHUB_SHA}` and `latest`.

## Important

Use this tool only for systems you own or have written authorization to test. Do not expose the panel publicly without an additional access-control layer.

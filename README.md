# DEU Security Lab

Docker/Portainer stack for authorized security testing of your own assets.

Includes:
- OpenAI Codex CLI
- Claude-BugHunter skills
- nuclei
- subfinder
- httpx
- katana
- dnsx
- ffuf
- nmap
- sqlmap
- amass
- jq, whois, dnsutils

## Portainer deployment

1. Open Portainer.
2. Go to **Stacks → Add stack**.
3. Select **Repository**.
4. Paste your GitHub repository URL.
5. Set branch: `main`.
6. Set compose path: `docker-compose.yml`.
7. Add environment variables:
   - `OPENAI_API_KEY`
   - `OPENAI_MODEL`
   - `TZ`
8. Deploy the stack.

## First run

Open container console in Portainer:

```bash
codex --version
nuclei -version
subfinder -version
httpx -version
katana -version
ffuf -V
nmap --version
```

Login Codex with OpenAI API key:

```bash
printenv OPENAI_API_KEY | codex login --with-api-key
codex login status
```

Start Codex:

```bash
codex
```

Example safe prompt:

```text
Я тестирую только свои сервисы. Проведи пассивный recon для example.com, без эксплуатации и без агрессивного сканирования. Сохрани результаты в /results/example.com.
```

## Important

Use this only for systems you own or have written authorization to test.
Do not expose this container publicly through Nginx Proxy Manager.

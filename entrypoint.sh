#!/usr/bin/env bash
set -e

mkdir -p /workspace /reports /results /root/.codex /root/.agents

echo "[deu-security-lab] Container started."
echo "[deu-security-lab] Workspace: /workspace"
echo "[deu-security-lab] Reports:   /reports"
echo "[deu-security-lab] Results:   /results"

if command -v nuclei >/dev/null 2>&1; then
  if [ ! -f /root/.local/share/nuclei/.templates_initialized ]; then
    echo "[deu-security-lab] Updating nuclei templates..."
    nuclei -update
    nuclei -update-templates
    nuclei -validate -t /root/.local/share/nuclei/templates
    mkdir -p /root/.local/share/nuclei
    touch /root/.local/share/nuclei/.templates_initialized
  fi
fi

if [ -n "${OPENAI_API_KEY:-}" ]; then
  echo "[deu-security-lab] OPENAI_API_KEY is set."
else
  echo "[deu-security-lab] WARNING: OPENAI_API_KEY is not set."
fi

exec "$@"

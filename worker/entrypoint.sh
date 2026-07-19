#!/usr/bin/env bash
set -euo pipefail

echo "[deu-security-worker] User: $(id -un) ($(id -u):$(id -g))"
echo "[deu-security-worker] Nuclei config: ${NUCLEI_CONFIG_DIR}"
echo "[deu-security-worker] Nuclei cache: ${NUCLEI_CACHE_DIR}"
echo "[deu-security-worker] Nuclei templates: ${NUCLEI_TEMPLATES_DIR}"

mkdir -p "${NUCLEI_CONFIG_DIR}" "${NUCLEI_CACHE_DIR}" "${NUCLEI_TEMPLATES_DIR}" /reports

HTTPX_PATH="$(command -v httpx || true)"
HTTPX_VERSION="$(httpx -version 2>&1 || true)"
echo "[deu-security-worker] httpx binary: ${HTTPX_PATH:-missing}"
echo "[deu-security-worker] httpx version: ${HTTPX_VERSION:-unavailable}"
if [[ -z "${HTTPX_PATH}" ]] || ! grep -Eiq 'projectdiscovery|current version' <<<"${HTTPX_VERSION}" || ! go version -m "${HTTPX_PATH}" 2>/dev/null | grep -Fq $'path\tgithub.com/projectdiscovery/httpx/cmd/httpx'; then
  echo "[deu-security-worker] ERROR: ProjectDiscovery httpx validation failed" >&2
  exit 1
fi
HTTPX_HELP="$(httpx -h 2>&1 || true)"
for flag in -silent -json -status-code -title -tech-detect -follow-redirects -timeout -retries; do
  if ! grep -Eq -- "${flag}" <<<"${HTTPX_HELP}"; then
    echo "[deu-security-worker] ERROR: ProjectDiscovery httpx does not support ${flag}" >&2
    exit 1
  fi
done

if command -v nuclei >/dev/null 2>&1; then
  if ! find "${NUCLEI_TEMPLATES_DIR}" -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
    echo "[deu-security-worker] Initializing nuclei templates..."
    nuclei -update-templates
  fi
  nuclei -validate -t "${NUCLEI_TEMPLATES_DIR}"
fi

exec "$@"

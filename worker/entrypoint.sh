#!/usr/bin/env bash
set -euo pipefail

echo "[deu-security-worker] User: $(id -un) ($(id -u):$(id -g))"
echo "[deu-security-worker] Nuclei config: ${NUCLEI_CONFIG_DIR}"
echo "[deu-security-worker] Nuclei cache: ${NUCLEI_CACHE_DIR}"
echo "[deu-security-worker] Nuclei templates: ${NUCLEI_TEMPLATES_DIR}"

mkdir -p "${NUCLEI_CONFIG_DIR}" "${NUCLEI_CACHE_DIR}" "${NUCLEI_TEMPLATES_DIR}" /reports

if command -v nuclei >/dev/null 2>&1; then
  if ! find "${NUCLEI_TEMPLATES_DIR}" -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
    echo "[deu-security-worker] Initializing nuclei templates..."
    nuclei -update-templates
  fi
  nuclei -validate -t "${NUCLEI_TEMPLATES_DIR}"
fi

exec "$@"

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
STATIC_EXTENSIONS = {
    ".avif",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
}
SIGNIFICANT_ROUTES = {"/login", "/privacy", "/terms", "/pravila"}
NUCLEI_WARNING = "Nuclei scan was not completed; vulnerability coverage is incomplete."
ADMIN_HOST_HINTS = {
    "docker": "Portainer",
    "portainer": "Portainer",
    "npm": "Nginx Proxy Manager",
    "nginx-proxy-manager": "Nginx Proxy Manager",
}
CDN_ASNS = ("cloudflare", "fastly", "akamai", "cloudfront", "google cloud cdn", "azure front door")
PRIVATE_CDN_NETS = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
]


def strip_ansi(value: str) -> str:
    return ANSI_RE.sub("", value)


def clean_lines(output: str) -> list[str]:
    return [strip_ansi(line).strip() for line in output.splitlines() if strip_ansi(line).strip()]


def has_nuclei_templates(templates_dir: str | Path) -> bool:
    root = Path(templates_dir)
    return root.is_dir() and any(path.suffix in {".yaml", ".yml"} for path in root.rglob("*") if path.is_file())


def nuclei_paths() -> dict[str, str]:
    home = Path.home()
    config_dir = Path(os.getenv("NUCLEI_CONFIG_DIR", os.getenv("XDG_CONFIG_HOME", str(home / ".config")) + "/nuclei"))
    cache_dir = Path(os.getenv("NUCLEI_CACHE_DIR", os.getenv("XDG_CACHE_HOME", str(home / ".cache")) + "/nuclei"))
    templates_dir = Path(os.getenv("NUCLEI_TEMPLATES_DIR", str(home / ".local/share/nuclei/templates")))
    return {"config": str(config_dir), "cache": str(cache_dir), "templates": str(templates_dir)}


def ensure_nuclei_templates(run_tool, cwd: str, templates_dir: str) -> tuple[bool, dict[str, Any]]:
    status: dict[str, Any] = {"templates_dir": templates_dir, "initialized": False, "validated": False}
    if not has_nuclei_templates(templates_dir):
        rc, stdout, stderr = run_tool(["nuclei", "-update-templates"], cwd)
        status.update({"update_returncode": rc, "update_stdout": strip_ansi(stdout), "update_stderr": strip_ansi(stderr), "initialized": rc == 0})
    if not has_nuclei_templates(templates_dir):
        status["reason"] = "templates missing after update"
        return False, status
    rc, stdout, stderr = run_tool(["nuclei", "-validate", "-t", templates_dir], cwd)
    status.update({"validate_returncode": rc, "validate_stdout": strip_ansi(stdout), "validate_stderr": strip_ansi(stderr), "validated": rc == 0})
    if rc != 0:
        status["reason"] = "template validation failed"
        return False, status
    return True, status


def classify_url(base_url: str, raw_value: str) -> tuple[str, str] | None:
    value = strip_ansi(raw_value).strip()
    if not value:
        return None
    if " " in value:
        value = value.split()[0]
    if value.startswith("//"):
        value = f"{urlparse(base_url).scheme}:{value}"
    if value.startswith("/"):
        value = urljoin(base_url, value)
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        repaired = urljoin(base_url, value if value.startswith("/") else f"/{value}")
        parsed = urlparse(repaired)
        value = repaired
    base_host = urlparse(base_url).hostname
    if parsed.hostname and base_host and parsed.hostname.lower() != base_host.lower():
        return "external_domains", value
    path = parsed.path or "/"
    suffix = Path(path).suffix.lower()
    if path.startswith("/_next/static/chunks/") or ("/_next/static/chunks/" in path and suffix == ".js"):
        return "javascript", value
    if suffix == ".js":
        return "javascript", value
    if suffix == ".css":
        return "css", value
    if suffix in STATIC_EXTENSIONS:
        return "static_assets", value
    lowered_path = path.lower()
    if re.search(r"(^|/)(api|graphql|rest|v[0-9])(/|$)", lowered_path):
        return "api_endpoints", value
    if re.search(r"(^|/)(login|signin|sign-in|auth|oauth|sso|account)(/|$)", lowered_path):
        return "authentication_endpoints", value
    return "pages", value


def normalize_katana_output(stdout: str, base_url: str) -> dict[str, Any]:
    buckets: dict[str, list[str]] = {
        "pages": [],
        "api_endpoints": [],
        "authentication_endpoints": [],
        "javascript": [],
        "css": [],
        "static_assets": [],
        "external_domains": [],
    }
    seen = {key: set() for key in buckets}
    for line in clean_lines(stdout):
        classified = classify_url(base_url, line)
        if not classified:
            continue
        bucket, value = classified
        if value not in seen[bucket]:
            seen[bucket].add(value)
            buckets[bucket].append(value)
    significant = []
    for bucket in ("pages", "authentication_endpoints"):
        for value in buckets[bucket]:
            path = urlparse(value).path.rstrip("/") or "/"
            if path in SIGNIFICANT_ROUTES or path in {"/login", "/privacy", "/terms", "/pravila"}:
                significant.append(value)
    buckets["significant_routes"] = sorted(set(significant))
    return buckets


def cloudflare_by_ip(ip_value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return any(address in network for network in PRIVATE_CDN_NETS)


def detect_cdn(host: str, resolved_ips: list[str] | None = None) -> dict[str, Any]:
    ips = resolved_ips or []
    if not ips:
        try:
            ips = sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
        except socket.gaierror:
            ips = []
    providers = []
    if any(cloudflare_by_ip(ip) for ip in ips):
        providers.append("Cloudflare")
    host_lower = host.lower()
    if any(hint in host_lower for hint in ("cloudflare", "cdn")) and "Cloudflare" not in providers:
        providers.append("Cloudflare/CDN")
    return {"is_cdn": bool(providers), "providers": providers, "resolved_ips": ips}


def classify_nmap_target(host: str, cdn: dict[str, Any], origin_ip: str | None, origin_confirmed: bool) -> dict[str, Any]:
    if origin_ip and origin_confirmed:
        return {"scope": "origin_infrastructure_exposure", "target": origin_ip, "edge_scan": False}
    if cdn.get("is_cdn"):
        return {
            "scope": "public_edge_exposure",
            "target": host,
            "edge_scan": True,
            "warning": "Target resolves to CDN/edge infrastructure; ports must not be attributed to the origin server.",
        }
    return {"scope": "origin_infrastructure_exposure", "target": host, "edge_scan": False}


def administrative_exposures(httpx_output: str) -> list[dict[str, Any]]:
    exposures = []
    for line in clean_lines(httpx_output):
        parsed = urlparse(line.split()[0] if line else "")
        host = parsed.hostname or line.split()[0].split("/")[0]
        labels = host.lower().split(".")
        panel = next((name for label in labels for hint, name in ADMIN_HOST_HINTS.items() if label == hint), None)
        if not panel:
            continue
        exposures.append(
            {
                "host": host,
                "panel": panel,
                "category": "Administrative Exposure",
                "severity": "Info",
                "checks": [
                    "public accessibility",
                    "VPN/access restrictions",
                    "MFA",
                    "version exposure",
                    "security headers",
                    "authentication page exposure",
                ],
                "credential_testing": "not performed",
            }
        )
    return exposures


def tool_outcome(tool: str, returncode: int | None, skipped: bool = False, reason: str = "") -> dict[str, Any]:
    if skipped:
        return {"status": "skipped", "reason": reason}
    return {"status": "completed" if returncode == 0 else "failed", "returncode": returncode}


def final_status(tool_status: dict[str, Any], warnings: list[str]) -> str:
    completed = [item for item in tool_status.values() if item.get("status") == "completed"]
    failed = [item for item in tool_status.values() if item.get("status") == "failed"]
    if failed and not completed:
        return "failed"
    if warnings or failed:
        return "completed_with_warnings"
    return "completed"


def methodology_metadata(root: str = "/opt/methodology/Claude-BugHunter", scan_type: str = "basic") -> dict[str, Any]:
    root_path = Path(root)
    files: list[str] = []
    if root_path.is_dir():
        for path in root_path.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".md", ".txt", ".yaml", ".yml", ".json"}:
                files.append(str(path))
            if len(files) >= 12:
                break
    version = ""
    if root_path.is_dir():
        try:
            version = subprocess.run(["git", "-C", str(root_path), "rev-parse", "--short", "HEAD"], check=False, capture_output=True, text=True).stdout.strip()
        except OSError:
            version = ""
    workflow = "web-application-safe-recon" if scan_type == "extended" else "web-application-baseline"
    checklist = [
        "validate target scope",
        "identify live HTTP services",
        "crawl user-visible routes",
        "run safe nuclei templates",
        "separate CDN edge exposure from origin exposure",
        "review administrative exposure without credential testing",
        "record limitations and failed tools",
    ]
    return {
        "methodology_name": "Claude-BugHunter",
        "methodology_version": version or "unavailable",
        "workflow": workflow,
        "used_skills": ["safe-recon", "web-route-review", "vulnerability-triage"],
        "checklist": checklist,
        "methodology_files": files,
    }


def parse_nuclei_findings(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in clean_lines(stdout):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        severity = str(info.get("severity", "info")).capitalize()
        findings.append(
            {
                "title": info.get("name", item.get("template-id", "nuclei finding")),
                "severity": severity if severity in {"Critical", "High", "Medium", "Low", "Info"} else "Info",
                "description": info.get("description") or "A nuclei template matched the target.",
                "recommendation": info.get("remediation") or "Review the affected service and apply the vendor or framework-specific fix.",
                "technical_details": {
                    "template_id": item.get("template-id"),
                    "matcher_name": item.get("matcher-name"),
                    "matched_at": item.get("matched-at"),
                    "type": item.get("type"),
                },
                "raw_output": item,
            }
        )
    return findings

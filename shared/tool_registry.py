from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Literal, Optional, Union
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, Field, ValidationError

from shared.pipeline_utils import (
    clean_lines,
    ensure_nuclei_templates,
    nuclei_paths,
    parse_nuclei_findings,
    strip_ansi,
)
from shared.security_utils import redact_secrets
from shared.target import ValidatedTarget

NMAP_ALLOWED_PORTS = os.getenv("NMAP_ALLOWED_PORTS", "80,443,8080,8443")
SAFE_NUCLEI_EXCLUDE_TAGS = "dos,intrusive,bruteforce,fuzz,headless"
MAX_OUTPUT_CHARS = 120_000


class ToolError(RuntimeError):
    pass


class DomainArgs(BaseModel):
    domain: str = Field(min_length=1, max_length=255)


class UrlArgs(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class DnsxArgs(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    resolver_file: Optional[str] = None
    timeout: int = Field(default=10, ge=1, le=60)
    retries: int = Field(default=1, ge=0, le=3)


class HttpxArgs(BaseModel):
    targets: list[str] = Field(default_factory=list)
    follow_redirects: bool = True
    status_code: bool = True
    title: bool = True
    tech_detect: bool = True
    timeout: int = Field(default=10, ge=1, le=60)
    retries: int = Field(default=1, ge=0, le=3)


class NmapArgs(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ports: Union[list[int], str] = Field(default=NMAP_ALLOWED_PORTS)
    scan_type: Literal["connect"] = "connect"
    timeout: int = Field(default=60, ge=10, le=600)


class FfufArgs(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    recursion: bool = False


class HttpRequestArgs(BaseModel):
    method: Literal["GET", "HEAD", "OPTIONS", "POST"] = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class OpenApiArgs(BaseModel):
    url: str


class JsExtractorArgs(BaseModel):
    url: str


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    schema: type[BaseModel]
    timeout: int
    rate_limit_seconds: float
    max_output: int
    description: str


class ToolRegistry:
    def __init__(self) -> None:
        self.definitions: dict[str, ToolDefinition] = {
            "subfinder": ToolDefinition("subfinder", DomainArgs, 600, 1.0, MAX_OUTPUT_CHARS, "Discover subdomains for an authorized domain."),
            "dnsx": ToolDefinition("dnsx", DnsxArgs, 300, 1.0, MAX_OUTPUT_CHARS, "Resolve DNS records for discovered hosts."),
            "httpx": ToolDefinition("httpx", HttpxArgs, 300, 1.0, MAX_OUTPUT_CHARS, "Probe live HTTP services and collect titles/tech."),
            "katana": ToolDefinition("katana", UrlArgs, 600, 1.0, MAX_OUTPUT_CHARS, "Crawl reachable HTTP routes with a shallow safe depth."),
            "nuclei": ToolDefinition("nuclei", UrlArgs, 900, 1.0, MAX_OUTPUT_CHARS, "Run safe nuclei templates with intrusive categories excluded."),
            "nmap": ToolDefinition("nmap", NmapArgs, 600, 1.0, MAX_OUTPUT_CHARS, "Check an allowlisted set of TCP ports."),
            "ffuf": ToolDefinition("ffuf", FfufArgs, 600, 2.0, MAX_OUTPUT_CHARS, "Run low-rate content discovery with a local wordlist."),
            "feroxbuster": ToolDefinition("feroxbuster", FfufArgs, 600, 2.0, MAX_OUTPUT_CHARS, "Run low-rate content discovery with a local wordlist."),
            "http_request": ToolDefinition("http_request", HttpRequestArgs, 120, 0.5, 40_000, "Make a single safe HTTP request."),
            "openapi_parser": ToolDefinition("openapi_parser", OpenApiArgs, 120, 0.5, 40_000, "Fetch and summarize an OpenAPI document."),
            "js_endpoint_extractor": ToolDefinition("js_endpoint_extractor", JsExtractorArgs, 120, 0.5, 40_000, "Fetch JavaScript and extract likely endpoints."),
            "header_tls_checker": ToolDefinition("header_tls_checker", UrlArgs, 120, 0.5, 40_000, "Collect response security headers and TLS-facing metadata."),
        }
        self._last_call: dict[str, float] = {}

    def list_for_prompt(self) -> list[dict[str, Any]]:
        return [
            {
                "name": item.name,
                "description": item.description,
                "schema": item.schema.model_json_schema(),
                "timeout": item.timeout,
                "max_output": item.max_output,
            }
            for item in self.definitions.values()
        ]

    def validate_call(self, name: str, args: dict[str, Any]) -> BaseModel:
        if name not in self.definitions:
            raise ToolError(f"Tool is not registered: {name}")
        try:
            return self.definitions[name].schema.model_validate(args)
        except ValidationError as exc:
            raise ToolError(f"Invalid arguments for {name}: {exc}") from exc

    def execute(self, name: str, args: dict[str, Any], target: ValidatedTarget, cwd: str) -> dict[str, Any]:
        parsed = self.validate_call(name, args)
        definition = self.definitions[name]
        elapsed = time.time() - self._last_call.get(name, 0)
        if elapsed < definition.rate_limit_seconds:
            time.sleep(definition.rate_limit_seconds - elapsed)
        self._last_call[name] = time.time()

        started = time.time()
        if name in {"subfinder", "dnsx", "httpx", "katana", "nuclei", "nmap", "ffuf", "feroxbuster"}:
            result = self._execute_process(name, parsed, target, cwd, definition)
        else:
            result = self._execute_builtin(name, parsed, definition)
        result["args"] = redact_secrets(parsed.model_dump())
        result.setdefault("normalized_arguments", redact_secrets(parsed.model_dump()))
        result.setdefault("status", "completed")
        result.setdefault("returncode", 0)
        result.setdefault("stdout", "")
        result.setdefault("stderr", "")
        result.setdefault("stdout_summary", summarize(json.dumps(redact_secrets(result), ensure_ascii=False)))
        result.setdefault("stderr_summary", "")
        result.setdefault("duration_seconds", round(time.time() - started, 3))
        result.setdefault("timeout", definition.timeout)
        result.setdefault("retry_count", 0)
        result.setdefault("actual_input_count", 1)
        result.setdefault("input_source", "arguments")
        result.setdefault("command_description", name)
        result.setdefault("binary_version", "builtin")
        result["tool"] = name
        return result

    def _run(self, command: list[str], cwd: str, timeout: int, max_output: int, retry_count: int = 0) -> dict[str, Any]:
        started = time.time()
        if not shutil.which(command[0]):
            return self._result("skipped", "binary_missing", None, "", "", timeout, started, retry_count, "binary not installed")
        attempts = 0
        last: dict[str, Any] = {}
        while attempts <= retry_count:
            process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return self._result("failed", "timeout", 124, stdout, f"{stderr}\nCommand timed out after {timeout} seconds", timeout, started, attempts, f"timeout after {timeout} seconds", max_output)
            stdout_clean = strip_ansi(stdout)[-max_output:]
            stderr_clean = strip_ansi(stderr)[-max_output:]
            category = failure_category(process.returncode, stdout_clean, stderr_clean)
            last = self._result("completed" if process.returncode == 0 else "failed", category, process.returncode, stdout_clean, stderr_clean, timeout, started, attempts, "", max_output)
            if process.returncode == 0 or category != "network_error":
                return last
            attempts += 1
        return last

    def _result(self, status: str, category: str, returncode: int | None, stdout: str, stderr: str, timeout: int, started: float, retry_count: int, reason: str = "", max_output: int = MAX_OUTPUT_CHARS) -> dict[str, Any]:
        stdout_clean = strip_ansi(stdout)[-max_output:]
        stderr_clean = strip_ansi(stderr)[-max_output:]
        return {
            "status": status,
            "failure_category": category if status != "completed" else None,
            "reason": reason,
            "returncode": returncode,
            "stdout": stdout_clean,
            "stderr": stderr_clean,
            "stdout_summary": summarize(stdout_clean),
            "stderr_summary": summarize(stderr_clean),
            "duration_seconds": round(time.time() - started, 3),
            "timeout": timeout,
            "retry_count": retry_count,
        }

    def _execute_process(self, name: str, args: BaseModel, target: ValidatedTarget, cwd: str, definition: ToolDefinition) -> dict[str, Any]:
        prepared = self._prepare_command(name, args, target, cwd)
        if prepared.get("skip"):
            return {
                "status": "skipped",
                "failure_category": prepared["failure_category"],
                "reason": prepared["reason"],
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "stdout_summary": "",
                "stderr_summary": "",
                "duration_seconds": 0,
                "timeout": definition.timeout,
                "retry_count": 0,
                "binary_version": self._binary_version(name),
                "normalized_arguments": redact_secrets(prepared.get("normalized_arguments", {})),
                "input_source": prepared.get("input_source", "none"),
                "actual_input_count": prepared.get("actual_input_count", 0),
                "command_description": prepared.get("command_description", name),
            }
        command = prepared["command"]
        result = self._run(command, cwd, prepared.get("timeout") or definition.timeout, definition.max_output, retry_count=prepared.get("retries", 0))
        result["command_description"] = prepared["command_description"]
        result["binary_version"] = self._binary_version(command[0])
        result["normalized_arguments"] = redact_secrets(prepared["normalized_arguments"])
        result["input_source"] = prepared.get("input_source", "arguments")
        result["actual_input_count"] = prepared.get("actual_input_count", 0)
        if name == "nuclei":
            result["findings"] = parse_nuclei_findings(result.get("stdout", ""))
        return result

    def _prepare_command(self, name: str, args: BaseModel, target: ValidatedTarget, cwd: str) -> dict[str, Any]:
        data = args.model_dump()
        if name == "subfinder":
            domain = normalize_host(data.get("domain") or target.host)
            return {"command": ["subfinder", "-silent", "-d", domain], "command_description": f"subfinder -d {domain}", "normalized_arguments": {"domain": domain}, "actual_input_count": 1, "input_source": "target"}
        if name == "dnsx":
            hosts = unique_valid_hosts(data.get("hosts") or [])
            if not hosts:
                return {"skip": True, "failure_category": "empty_input", "reason": "No discovered hosts to resolve", "normalized_arguments": {"hosts": []}, "actual_input_count": 0, "input_source": "discovered_hosts", "command_description": "dnsx skipped"}
            input_path = os.path.join(cwd, "dnsx-input.txt")
            with open(input_path, "w", encoding="utf-8") as file:
                file.write("\n".join(hosts) + "\n")
            command = ["dnsx", "-silent", "-a", "-l", input_path, "-retry", str(data.get("retries", 1))]
            if data.get("resolver_file"):
                command.extend(["-r", _safe_artifact_path(cwd, data["resolver_file"])])
            return {"command": command, "command_description": f"dnsx -l dnsx-input.txt ({len(hosts)} hosts)", "normalized_arguments": {"hosts": hosts, "timeout": data.get("timeout"), "retries": data.get("retries")}, "actual_input_count": len(hosts), "input_source": "discovered_hosts", "timeout": data.get("timeout", definition_timeout(name)), "retries": data.get("retries", 0)}
        if name == "httpx":
            targets = unique_http_targets(data.get("targets") or [], target.url)
            if not targets:
                targets = [normalize_base_url(target.url)]
            input_path = os.path.join(cwd, "httpx-input.txt")
            with open(input_path, "w", encoding="utf-8") as file:
                file.write("\n".join(targets) + "\n")
            command = ["httpx", "-silent", "-l", input_path, "-timeout", str(data.get("timeout", 10)), "-retries", str(data.get("retries", 1))]
            if data.get("follow_redirects"):
                command.append("-follow-redirects")
            if data.get("status_code"):
                command.append("-status-code")
            if data.get("title"):
                command.append("-title")
            if data.get("tech_detect"):
                command.append("-tech-detect")
            return {"command": command, "command_description": f"httpx -l httpx-input.txt ({len(targets)} targets)", "normalized_arguments": {**data, "targets": targets}, "actual_input_count": len(targets), "input_source": "reachable_candidates", "timeout": data.get("timeout", definition_timeout(name)), "retries": data.get("retries", 0)}
        if name == "katana":
            url = normalize_base_url(data.get("url") or target.url)
            return {"command": ["katana", "-silent", "-u", url, "-d", "2"], "command_description": f"katana -u {url} -d 2", "normalized_arguments": {"url": url}, "actual_input_count": 1, "input_source": "reachable_http"}
        if name == "nuclei":
            paths = nuclei_paths()
            if shutil.which("nuclei"):
                ensure_nuclei_templates(lambda cmd, run_cwd: self._legacy_run(cmd, run_cwd), cwd, paths["templates"])
            url = normalize_base_url(data.get("url") or target.url)
            return {"command": ["nuclei", "-silent", "-u", url, "-t", paths["templates"], "-exclude-tags", SAFE_NUCLEI_EXCLUDE_TAGS, "-jsonl"], "command_description": f"nuclei -u {url} -t templates -exclude-tags safe-list", "normalized_arguments": {"url": url, "exclude_tags": SAFE_NUCLEI_EXCLUDE_TAGS}, "actual_input_count": 1, "input_source": "reachable_http"}
        if name == "nmap":
            host = normalize_host(data.get("host"))
            if not host:
                return {"skip": True, "failure_category": "invalid_arguments", "reason": "Nmap host is required", "normalized_arguments": data, "actual_input_count": 0, "input_source": "planner", "command_description": "nmap skipped"}
            if not valid_host(host):
                return {"skip": True, "failure_category": "invalid_arguments", "reason": f"Nmap host is not a valid domain or IP: {host}", "normalized_arguments": data, "actual_input_count": 0, "input_source": "planner", "command_description": "nmap skipped"}
            ports = data.get("ports") or NMAP_ALLOWED_PORTS
            if isinstance(ports, list):
                ports_value = ",".join(str(port) for port in ports)
            else:
                ports_value = str(ports)
            return {"command": ["nmap", "-Pn", "-sT", "-p", ports_value, host], "command_description": f"nmap -Pn -sT -p {ports_value} {host}", "normalized_arguments": {"host": host, "ports": ports_value, "scan_type": data.get("scan_type"), "timeout": data.get("timeout")}, "actual_input_count": 1, "input_source": "resolved_host", "timeout": data.get("timeout", definition_timeout(name))}
        if name == "ffuf":
            command = ["ffuf", "-s", "-rate", "20", "-w", data["wordlist"], "-u", data["url"]]
            return command + (["-recursion"] if data.get("recursion") else [])
        if name == "feroxbuster":
            command = ["feroxbuster", "-q", "--rate-limit", "20", "-w", data["wordlist"], "-u", data["url"]]
            return command + (["--depth", "2"] if data.get("recursion") else ["--depth", "1"])
        raise ToolError(f"Unsupported process tool: {name}")

    def _legacy_run(self, command: list[str], cwd: str) -> tuple[int, str, str]:
        result = self._run(command, cwd, 900, MAX_OUTPUT_CHARS)
        return int(result.get("returncode") or 0), result.get("stdout", ""), result.get("stderr", "")

    def _binary_version(self, name: str) -> str:
        binary = name
        if not shutil.which(binary):
            return "missing"
        version_args = {
            "nmap": ["--version"],
            "curl": ["--version"],
        }.get(binary, ["-version"])
        try:
            process = subprocess.run([binary, *version_args], capture_output=True, text=True, timeout=10, check=False)
            return summarize(strip_ansi((process.stdout or process.stderr)[:2000]))
        except Exception as exc:
            return f"version unavailable: {exc}"

    def _execute_builtin(self, name: str, args: BaseModel, definition: ToolDefinition) -> dict[str, Any]:
        data = args.model_dump()
        if name == "http_request":
            response = requests.request(
                data["method"],
                data["url"],
                headers={k: v for k, v in data.get("headers", {}).items() if k.lower() not in {"authorization", "cookie"}},
                data=data.get("body") if data["method"] == "POST" else None,
                timeout=definition.timeout,
                allow_redirects=False,
            )
            return {
                "status": "completed",
                "status_code": response.status_code,
                "headers": redact_secrets(dict(response.headers)),
                "body_preview": strip_ansi(response.text[:5000]),
            }
        if name == "openapi_parser":
            response = requests.get(data["url"], timeout=definition.timeout)
            response.raise_for_status()
            doc = response.json() if response.text.lstrip().startswith("{") else {}
            paths = sorted((doc.get("paths") or {}).keys())[:200]
            return {"status": "completed", "title": (doc.get("info") or {}).get("title"), "version": (doc.get("info") or {}).get("version"), "paths": paths}
        if name == "js_endpoint_extractor":
            response = requests.get(data["url"], timeout=definition.timeout)
            response.raise_for_status()
            endpoints = sorted(set(re.findall(r"['\"]((?:/|https?://)[A-Za-z0-9_./?&=%:-]{3,})['\"]", response.text)))[:300]
            return {"status": "completed", "endpoints": endpoints}
        if name == "header_tls_checker":
            response = requests.get(data["url"], timeout=definition.timeout, allow_redirects=False)
            headers = dict(response.headers)
            checks = {
                "strict_transport_security": "strict-transport-security" in {k.lower() for k in headers},
                "content_security_policy": "content-security-policy" in {k.lower() for k in headers},
                "x_frame_options": "x-frame-options" in {k.lower() for k in headers},
            }
            return {"status": "completed", "status_code": response.status_code, "headers": redact_secrets(headers), "checks": checks}
        raise ToolError(f"Unsupported builtin tool: {name}")


def _safe_artifact_path(cwd: str, value: str) -> str:
    candidate = os.path.abspath(os.path.join(cwd, value))
    root = os.path.abspath(cwd)
    if not candidate.startswith(root + os.sep):
        raise ToolError("input_file must be inside scan artifact directory")
    return candidate


def normalize_host(value: Optional[str]) -> str:
    if not value:
        return ""
    parsed = urlparse(str(value).strip())
    host = parsed.hostname if parsed.scheme else str(value).strip().split("/")[0]
    return (host or "").strip().strip(".")


def normalize_base_url(value: str) -> str:
    raw = str(value).strip()
    parsed = urlparse(raw)
    if not parsed.scheme:
        return f"https://{normalize_host(raw)}"
    host = parsed.hostname or ""
    if not host:
        return raw
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}"


def valid_host(value: str) -> bool:
    host = normalize_host(value)
    if not host:
        return False
    if IP_RE.match(host):
        parts = host.split(".")
        return all(0 <= int(part) <= 255 for part in parts)
    return bool(DOMAIN_RE.match(host))


def unique_valid_hosts(values: list[str]) -> list[str]:
    seen = set()
    hosts = []
    for value in values:
        host = normalize_host(value)
        if host and host not in seen and valid_host(host):
            seen.add(host)
            hosts.append(host)
    return hosts


def unique_http_targets(values: list[str], fallback_url: str) -> list[str]:
    seen = set()
    targets = []
    for value in [*values, fallback_url]:
        if not value:
            continue
        url = normalize_base_url(value)
        if url not in seen and normalize_host(url):
            seen.add(url)
            targets.append(url)
    return targets


def summarize(value: str, limit: int = 1200) -> str:
    lines = clean_lines(value)
    return "\n".join(lines[:20])[:limit]


def failure_category(returncode: int | None, stdout: str, stderr: str) -> str:
    if returncode == 0:
        return ""
    text = f"{stdout}\n{stderr}".lower()
    if returncode == 124 or "timeout" in text or "deadline" in text:
        return "timeout"
    if any(term in text for term in ("no such host", "connection refused", "connection reset", "network is unreachable", "temporary failure", "i/o timeout")):
        return "network_error"
    if any(term in text for term in ("invalid", "unknown flag", "usage:", "requires", "missing")):
        return "invalid_arguments"
    return "tool_error"


def definition_timeout(name: str) -> int:
    return {"dnsx": 300, "httpx": 300, "nmap": 600}.get(name, 300)


def normalize_finding_fingerprint(finding: dict[str, Any]) -> str:
    source = "|".join(
        [
            str(finding.get("category") or finding.get("title") or "").lower().strip(),
            str(finding.get("endpoint") or finding.get("technical_details", {}).get("matched_at") or "").lower().strip(),
            str(finding.get("parameter") or "").lower().strip(),
            str(finding.get("cwe") or finding.get("technical_details", {}).get("template_id") or "").lower().strip(),
            str(finding.get("evidence_signature") or finding.get("description") or "")[:128].lower().strip(),
        ]
    )
    import hashlib

    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:32]

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Literal, Optional
from urllib.parse import urljoin, urlparse

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


class FileInputArgs(BaseModel):
    input_file: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None


class NmapArgs(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ports: str = Field(default=NMAP_ALLOWED_PORTS, pattern=r"^[0-9, -]+$")


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
            "dnsx": ToolDefinition("dnsx", FileInputArgs, 300, 1.0, MAX_OUTPUT_CHARS, "Resolve DNS records for discovered hosts."),
            "httpx": ToolDefinition("httpx", FileInputArgs, 300, 1.0, MAX_OUTPUT_CHARS, "Probe live HTTP services and collect titles/tech."),
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

        if name in {"subfinder", "dnsx", "httpx", "katana", "nuclei", "nmap", "ffuf", "feroxbuster"}:
            result = self._execute_process(name, parsed, target, cwd, definition)
        else:
            result = self._execute_builtin(name, parsed, definition)
        result["args"] = redact_secrets(parsed.model_dump())
        result["tool"] = name
        return result

    def _run(self, command: list[str], cwd: str, timeout: int, max_output: int) -> dict[str, Any]:
        if not shutil.which(command[0]):
            return {"status": "skipped", "reason": "binary not installed", "returncode": None, "stdout": "", "stderr": ""}
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return {
                "status": "failed",
                "reason": f"timeout after {timeout} seconds",
                "returncode": 124,
                "stdout": strip_ansi(stdout)[-max_output:],
                "stderr": strip_ansi(stderr)[-max_output:],
            }
        return {
            "status": "completed" if process.returncode == 0 else "failed",
            "returncode": process.returncode,
            "stdout": strip_ansi(stdout)[-max_output:],
            "stderr": strip_ansi(stderr)[-max_output:],
        }

    def _execute_process(self, name: str, args: BaseModel, target: ValidatedTarget, cwd: str, definition: ToolDefinition) -> dict[str, Any]:
        command = self._build_command(name, args, target, cwd)
        result = self._run(command, cwd, definition.timeout, definition.max_output)
        result["command_description"] = " ".join(command[:2]) if len(command) > 1 else command[0]
        if name == "nuclei":
            result["findings"] = parse_nuclei_findings(result.get("stdout", ""))
        return result

    def _build_command(self, name: str, args: BaseModel, target: ValidatedTarget, cwd: str) -> list[str]:
        data = args.model_dump()
        if name == "subfinder":
            return ["subfinder", "-silent", "-d", data.get("domain") or target.host]
        if name == "dnsx":
            if data.get("input_file"):
                return ["dnsx", "-silent", "-a", "-l", _safe_artifact_path(cwd, data["input_file"])]
            return ["dnsx", "-silent", "-a", "-d", data.get("domain") or target.host]
        if name == "httpx":
            command = ["httpx", "-silent", "-follow-redirects", "-status-code", "-title", "-tech-detect"]
            if data.get("input_file"):
                return command + ["-l", _safe_artifact_path(cwd, data["input_file"])]
            return command + ["-u", data.get("url") or target.url]
        if name == "katana":
            return ["katana", "-silent", "-u", data.get("url") or target.url, "-d", "2"]
        if name == "nuclei":
            paths = nuclei_paths()
            if shutil.which("nuclei"):
                ensure_nuclei_templates(lambda cmd, run_cwd: self._legacy_run(cmd, run_cwd), cwd, paths["templates"])
            return ["nuclei", "-silent", "-u", data.get("url") or target.url, "-t", paths["templates"], "-exclude-tags", SAFE_NUCLEI_EXCLUDE_TAGS, "-jsonl"]
        if name == "nmap":
            return ["nmap", "-Pn", "-sT", "-p", data.get("ports") or NMAP_ALLOWED_PORTS, data.get("host") or target.host]
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

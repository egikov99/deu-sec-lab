from __future__ import annotations

import html
import json
import os
import pwd
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from shared.db import SessionLocal
from shared.models import Project, Scan
from shared.pipeline_utils import (
    NUCLEI_WARNING,
    administrative_exposures,
    classify_nmap_target,
    clean_lines,
    detect_cdn,
    ensure_nuclei_templates,
    final_status,
    methodology_metadata,
    normalize_katana_output,
    nuclei_paths,
    parse_nuclei_findings,
    strip_ansi,
    tool_outcome,
)
from shared.schema import ensure_schema
from shared.target import ValidatedTarget, validate_target

REPORTS_ROOT = os.getenv("REPORTS_ROOT", "/reports")

SAFE_NUCLEI_EXCLUDE_TAGS = "dos,intrusive,bruteforce,fuzz,headless"
NMAP_ALLOWED_PORTS = os.getenv("NMAP_ALLOWED_PORTS", "80,443,8080,8443")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def append_log(scan: Scan, message: str) -> None:
    scan.logs = (scan.logs or "") + f"[{utc_now().isoformat()}] {strip_ansi(message)}\n"


def run_tool(command: list[str], cwd: str) -> tuple[int, str, str]:
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=900)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return 124, stdout, f"{stderr}\nCommand timed out after 900 seconds"
    return process.returncode, stdout, stderr


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def build_command(tool: str, target: ValidatedTarget, input_file: str | None = None, nmap_target: str | None = None) -> list[str]:
    if tool == "httpx":
        command = ["httpx", "-silent", "-follow-redirects", "-status-code", "-title", "-tech-detect"]
        if input_file:
            return command + ["-l", input_file]
        return command + ["-u", target.url]
    if tool == "katana":
        return ["katana", "-silent", "-u", target.url, "-d", "2"]
    if tool == "nuclei":
        templates_dir = nuclei_paths()["templates"]
        return [
            "nuclei",
            "-silent",
            "-u",
            target.url,
            "-t",
            templates_dir,
            "-exclude-tags",
            SAFE_NUCLEI_EXCLUDE_TAGS,
            "-jsonl",
        ]
    if tool == "subfinder":
        return ["subfinder", "-silent", "-d", target.host]
    if tool == "dnsx":
        if input_file:
            return ["dnsx", "-silent", "-a", "-l", input_file]
        return ["dnsx", "-silent", "-a", "-d", target.host]
    if tool == "nmap":
        return ["nmap", "-Pn", "-sT", "-p", NMAP_ALLOWED_PORTS, nmap_target or target.host]
    raise ValueError(f"Unsupported tool: {tool}")


def write_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)


def build_coverage(tool_status: dict[str, Any]) -> dict[str, Any]:
    return {
        "successfully_completed_tools": [name for name, status in tool_status.items() if status.get("status") == "completed"],
        "failed_tools": [name for name, status in tool_status.items() if status.get("status") == "failed"],
        "skipped_tools": [name for name, status in tool_status.items() if status.get("status") == "skipped"],
    }


def worker_identity() -> dict[str, Any]:
    uid = os.getuid()
    gid = os.getgid()
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = str(uid)
    return {"username": username, "uid": uid, "gid": gid}


def write_reports(
    report_dir: str,
    scan: Scan,
    target: ValidatedTarget,
    findings: list[dict[str, Any]],
    raw_outputs: dict[str, Any],
) -> None:
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    severity_counts = {severity: sum(1 for finding in findings if finding.get("severity") == severity) for severity in severity_order}
    warnings = scan.warnings or []
    tool_status = scan.tool_status or {}
    metadata = scan.scan_metadata or {}
    normalized = scan.normalized_outputs or {}
    coverage = build_coverage(tool_status)
    raw_artifacts = {name: value.get("artifacts", {}) for name, value in raw_outputs.items() if isinstance(value, dict)}
    cdn = normalized.get("cdn_detection", {})
    admin = normalized.get("administrative_exposure", [])
    nmap = normalized.get("nmap", {})

    summary_lines = [
        "# Security scan report",
        "",
        f"- Target: `{target.url}`",
        f"- Scan type: `{scan.scan_type}`",
        f"- Status: `{scan.status}`",
        f"- Findings: `{len(findings)}`",
        f"- Methodology: `{metadata.get('methodology_name', 'not recorded')}` `{metadata.get('methodology_version', '')}`",
        "",
        "## Coverage",
        "",
        f"- Successfully completed tools: `{', '.join(coverage['successfully_completed_tools']) or 'none'}`",
        f"- Failed tools: `{', '.join(coverage['failed_tools']) or 'none'}`",
        f"- Skipped tools: `{', '.join(coverage['skipped_tools']) or 'none'}`",
        "",
        "## Warnings",
        "",
        *(f"- {warning}" for warning in warnings),
        *([] if warnings else ["- None"]),
        "",
        "## CDN detection",
        "",
        f"- CDN detected: `{bool(cdn.get('is_cdn'))}`",
        f"- Providers: `{', '.join(cdn.get('providers', [])) or 'none'}`",
        f"- Resolved IPs: `{', '.join(cdn.get('resolved_ips', [])) or 'not recorded'}`",
        "",
        "## Limitations",
        "",
        "- Safe templates only; intrusive, DoS, brute force, fuzzing, and headless nuclei checks are excluded.",
        "- Credentials and brute force checks are not performed.",
        "- CDN/edge port exposure is not attributed to the origin server unless explicit origin IP authorization is configured.",
        "",
        "## Public edge exposure",
        "",
        f"- Nmap scope: `{nmap.get('scope', 'not run')}`",
        f"- Edge scan: `{bool(nmap.get('edge_scan'))}`",
        f"- Target scanned: `{nmap.get('target', 'not run')}`",
        "",
        "## Origin infrastructure exposure",
        "",
        f"- Origin scan target: `{nmap.get('origin_ip') or 'not configured'}`",
        f"- Origin scan confirmed: `{bool(nmap.get('origin_scan_confirmed'))}`",
        "",
        "## Informational observations",
        "",
        *(f"- Administrative Exposure: {item['host']} ({item['panel']}); checks: {', '.join(item['checks'])}; credential testing: {item['credential_testing']}." for item in admin),
        *([] if admin else ["- None"]),
        "",
        "## Severity summary",
        "",
        *[f"- {severity}: {severity_counts[severity]}" for severity in severity_order],
        "",
        "## Findings",
        "",
    ]
    if findings:
        for finding in findings:
            summary_lines.extend(
                [
                    f"### {finding['severity']} - {finding['title']}",
                    "",
                    finding.get("description", ""),
                    "",
                    f"Recommendation: {finding.get('recommendation', '')}",
                    "",
                    "Technical details:",
                    "",
                    "```json",
                    json.dumps(finding.get("technical_details", {}), indent=2, ensure_ascii=False),
                    "```",
                    "",
                ]
            )
    else:
        summary_lines.append("No findings were produced by the enabled safe checks.")
    summary_lines.extend(
        [
            "",
            "## Raw artifact links",
            "",
            *[f"- {tool}: {json.dumps(paths, ensure_ascii=False)}" for tool, paths in raw_artifacts.items()],
        ]
    )

    summary_md = "\n".join(summary_lines)
    with open(os.path.join(report_dir, "summary.md"), "w", encoding="utf-8") as file:
        file.write(summary_md)

    html_findings = "".join(
        f"<section><h3>{html.escape(finding['severity'])}: {html.escape(finding['title'])}</h3>"
        f"<p>{html.escape(finding.get('description', ''))}</p>"
        f"<p><strong>Recommendation:</strong> {html.escape(finding.get('recommendation', ''))}</p>"
        f"<pre>{html.escape(json.dumps(finding.get('technical_details', {}), indent=2, ensure_ascii=False))}</pre></section>"
        for finding in findings
    ) or "<p>No findings were produced by the enabled safe checks.</p>"
    report_html = (
        "<!doctype html><html><head><meta charset='utf-8'><title>Security scan report</title>"
        "<style>body{font-family:Arial,sans-serif;margin:32px;line-height:1.5;color:#111827}"
        "section{border-top:1px solid #d1d5db;padding:16px 0}pre{background:#f3f4f6;padding:12px;overflow:auto}</style>"
        f"</head><body><h1>Security scan report</h1><p><strong>Target:</strong> {html.escape(target.url)}</p>"
        f"<p><strong>Status:</strong> {html.escape(scan.status)}</p>"
        f"<p><strong>Warnings:</strong> {html.escape('; '.join(warnings) or 'None')}</p>"
        f"<p><strong>Findings:</strong> {len(findings)}</p>{html_findings}</body></html>"
    )
    with open(os.path.join(report_dir, "report.html"), "w", encoding="utf-8") as file:
        file.write(report_html)

    write_json(os.path.join(report_dir, "findings.json"), findings)
    write_json(os.path.join(report_dir, "raw.json"), raw_outputs)
    write_json(os.path.join(report_dir, "normalized.json"), normalized)
    write_json(os.path.join(report_dir, "metadata.json"), metadata)
    with open(os.path.join(report_dir, "logs.txt"), "w", encoding="utf-8") as file:
        file.write(scan.logs or "")

    try:
        pdf = canvas.Canvas(os.path.join(report_dir, "report.pdf"), pagesize=letter)
        text = pdf.beginText(40, 750)
        text.setFont("Helvetica", 10)
        for line in summary_md.splitlines()[:65]:
            text.textLine(line[:110])
        pdf.drawText(text)
        pdf.save()
    except Exception:
        pass


def run_scan_task(scan_id: int) -> None:
    ensure_schema()
    session = SessionLocal()
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        session.close()
        return

    report_dir = os.path.join(REPORTS_ROOT, str(scan.project_id), str(scan.id))
    os.makedirs(report_dir, exist_ok=True)
    scan.report_dir = os.path.relpath(report_dir, REPORTS_ROOT)
    scan.status = "running"
    scan.current_step = "Starting scan"
    scan.progress = 5
    scan.started_at = utc_now()
    scan.logs = ""
    session.commit()

    try:
        target = validate_target(scan.target, allow_private=os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true")
        project = session.query(Project).filter(Project.id == scan.project_id).first()
        origin_ip = project.origin_ip if project else None
        origin_scan_confirmed = bool(project.origin_scan_confirmed) if project else False
        methodology = methodology_metadata(scan_type=scan.scan_type)
        methodology["worker_user"] = worker_identity()
        methodology["nuclei_paths"] = nuclei_paths()
        scan.scan_metadata = methodology
        steps = [
            {"name": "Validate target", "tool": None},
            {"name": "HTTP probing", "tool": "httpx"},
            {"name": "Crawl target", "tool": "katana"},
            {"name": "Safe nuclei checks", "tool": "nuclei"},
            {"name": "Generate report", "tool": None},
        ]
        if scan.scan_type == "extended" and target.is_domain:
            steps.insert(1, {"name": "Subdomain discovery", "tool": "subfinder"})
            steps.insert(2, {"name": "DNS probing", "tool": "dnsx"})
        if scan.scan_type == "extended":
            steps.insert(-1, {"name": "Nmap allowed ports", "tool": "nmap"})

        findings: list[dict[str, Any]] = []
        raw_outputs: dict[str, Any] = {}
        normalized_outputs: dict[str, Any] = {}
        tool_status: dict[str, Any] = {}
        warnings: list[str] = []
        generated_files: dict[str, str] = {}
        cdn_detection = detect_cdn(target.host)
        normalized_outputs["cdn_detection"] = cdn_detection

        for index, step in enumerate(steps, start=1):
            scan.current_step = step["name"]
            scan.progress = min(95, int((index / len(steps)) * 100))
            session.commit()

            tool = step["tool"]
            if tool is None:
                append_log(scan, step["name"])
                session.commit()
                continue

            if not tool_available(tool):
                append_log(scan, f"Skipping {tool}: binary is not installed in the worker image")
                raw_outputs[tool] = {"skipped": True, "reason": "binary not installed"}
                tool_status[tool] = tool_outcome(tool, None, skipped=True, reason="binary not installed")
                if tool == "nuclei":
                    warnings.append(NUCLEI_WARNING)
                session.commit()
                continue

            input_file = generated_files.get("subfinder") if tool in {"dnsx", "httpx"} else None
            if tool == "dnsx" and not input_file:
                input_file = os.path.join(report_dir, "target-hosts.txt")
                with open(input_file, "w", encoding="utf-8") as file:
                    file.write(f"{target.host}\n")
            nmap_classification: dict[str, Any] = {}
            if tool == "nuclei":
                paths = nuclei_paths()
                append_log(scan, f"Nuclei paths: config={paths['config']} cache={paths['cache']} templates={paths['templates']}")
                templates_ok, templates_status = ensure_nuclei_templates(run_tool, report_dir, paths["templates"])
                normalized_outputs["nuclei_templates"] = templates_status
                if not templates_ok:
                    append_log(scan, f"Skipping nuclei: {templates_status.get('reason', 'templates unavailable')}")
                    raw_outputs[tool] = {"skipped": True, "reason": templates_status.get("reason"), "templates": templates_status}
                    tool_status[tool] = tool_outcome(tool, None, skipped=True, reason=templates_status.get("reason", "templates unavailable"))
                    warnings.append(NUCLEI_WARNING)
                    session.commit()
                    continue
            if tool == "nmap":
                nmap_classification = classify_nmap_target(target.host, cdn_detection, origin_ip, origin_scan_confirmed)
                if nmap_classification.get("warning"):
                    warnings.append(nmap_classification["warning"])
                nmap_classification["origin_ip"] = origin_ip
                nmap_classification["origin_scan_confirmed"] = origin_scan_confirmed
                normalized_outputs["nmap"] = nmap_classification
            command = build_command(tool, target, input_file=input_file, nmap_target=nmap_classification.get("target") if nmap_classification else None)
            append_log(scan, f"Running whitelisted tool: {tool}")
            session.commit()

            rc, stdout, stderr = run_tool(command, report_dir)
            clean_stdout = strip_ansi(stdout)
            clean_stderr = strip_ansi(stderr)
            tool_status[tool] = tool_outcome(tool, rc)
            log_path = os.path.join(report_dir, f"{tool}.log")
            stdout_path = os.path.join(report_dir, f"{tool}.out")
            with open(log_path, "w", encoding="utf-8") as file:
                file.write(stdout)
                file.write(stderr)
            with open(stdout_path, "w", encoding="utf-8") as file:
                file.write(stdout)
            generated_files[tool] = stdout_path
            raw_outputs[tool] = {
                "returncode": rc,
                "stdout": clean_stdout,
                "stderr": clean_stderr,
                "artifacts": {
                    "raw_log": os.path.relpath(log_path, report_dir),
                    "raw_stdout": os.path.relpath(stdout_path, report_dir),
                },
            }

            if clean_stdout:
                append_log(scan, clean_stdout[-4000:])
            if clean_stderr:
                append_log(scan, clean_stderr[-4000:])
            if rc != 0:
                append_log(scan, f"{tool} exited with code {rc}; continuing with remaining safe steps")
                if tool == "nuclei":
                    warnings.append(NUCLEI_WARNING)
            if tool == "nuclei":
                findings.extend(parse_nuclei_findings(clean_stdout))
            if tool == "katana":
                normalized_outputs["katana"] = normalize_katana_output(clean_stdout, target.url)
            if tool == "httpx":
                normalized_outputs["administrative_exposure"] = administrative_exposures(clean_stdout)
            session.commit()

        scan.findings = findings
        scan.warnings = sorted(set(warnings))
        scan.tool_status = tool_status
        scan.normalized_outputs = normalized_outputs
        scan.status = final_status(tool_status, scan.warnings)
        warning_suffix = " Vulnerability coverage is incomplete." if NUCLEI_WARNING in scan.warnings else ""
        scan.summary = f"Scan {scan.status} for {target.url}. Findings: {len(findings)}.{warning_suffix}"
        scan.current_step = "Completed"
        scan.progress = 100
        scan.finished_at = utc_now()
        append_log(scan, "Scan finished")
        write_reports(report_dir, scan, target, findings, raw_outputs)

        if os.getenv("OPENAI_API_KEY"):
            try:
                from openai import OpenAI

                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                prompt = (
                    "Create a concise internal security scan summary. "
                    "Use the recorded methodology checklist and warnings. "
                    f"Target: {target.url}. Scan type: {scan.scan_type}. Status: {scan.status}. "
                    f"Warnings: {json.dumps(scan.warnings, ensure_ascii=False)}. "
                    f"Methodology: {json.dumps(methodology, ensure_ascii=False)}. "
                    f"Findings JSON: {json.dumps(findings[:20], ensure_ascii=False)}"
                )
                response = client.responses.create(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), input=prompt)
                if response.output_text:
                    scan.summary = response.output_text
                    write_reports(report_dir, scan, target, findings, raw_outputs)
            except Exception as exc:
                append_log(scan, f"AI summary skipped: {exc}")

        session.commit()
    except Exception as exc:
        scan.status = "failed"
        scan.current_step = "Failed"
        scan.finished_at = utc_now()
        append_log(scan, f"Error: {exc}")
        with open(os.path.join(report_dir, "logs.txt"), "w", encoding="utf-8") as file:
            file.write(scan.logs or "")
        session.commit()
    finally:
        session.close()

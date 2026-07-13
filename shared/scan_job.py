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
    try:
        from shared.claude_bughunter_runner import ClaudeBugHunterAgentRunner

        ClaudeBugHunterAgentRunner(session=session, scan=scan, report_dir=report_dir).run()
    except Exception as exc:
        scan.status = "failed"
        scan.phase = "failed"
        scan.current_step = "Failed"
        scan.finished_at = utc_now()
        append_log(scan, f"Error: {exc}")
        with open(os.path.join(report_dir, "logs.txt"), "w", encoding="utf-8") as file:
            file.write(scan.logs or "")
        session.commit()
    finally:
        session.close()

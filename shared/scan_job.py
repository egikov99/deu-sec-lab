import html
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from shared.db import SessionLocal
from shared.models import Scan
from shared.target import ValidatedTarget, validate_target

REPORTS_ROOT = os.getenv("REPORTS_ROOT", "/reports")

SAFE_NUCLEI_EXCLUDE_TAGS = "dos,intrusive,bruteforce,fuzz,headless"
NMAP_ALLOWED_PORTS = os.getenv("NMAP_ALLOWED_PORTS", "80,443,8080,8443")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def append_log(scan: Scan, message: str) -> None:
    scan.logs = (scan.logs or "") + f"[{utc_now().isoformat()}] {message}\n"


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


def build_command(tool: str, target: ValidatedTarget, input_file: str | None = None) -> list[str]:
    if tool == "httpx":
        command = ["httpx", "-silent", "-follow-redirects", "-status-code", "-title", "-tech-detect"]
        if input_file:
            return command + ["-l", input_file]
        return command + ["-u", target.url]
    if tool == "katana":
        return ["katana", "-silent", "-u", target.url, "-d", "2"]
    if tool == "nuclei":
        return [
            "nuclei",
            "-silent",
            "-u",
            target.url,
            "-t",
            "/root/.local/share/nuclei/templates",
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
        return ["nmap", "-Pn", "-sT", "-p", NMAP_ALLOWED_PORTS, target.host]
    raise ValueError(f"Unsupported tool: {tool}")


def parse_nuclei_findings(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
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


def write_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)


def write_reports(report_dir: str, scan: Scan, target: ValidatedTarget, findings: list[dict[str, Any]], raw_outputs: dict[str, Any]) -> None:
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    severity_counts = {severity: sum(1 for finding in findings if finding.get("severity") == severity) for severity in severity_order}

    summary_lines = [
        "# Security scan report",
        "",
        f"- Target: `{target.url}`",
        f"- Scan type: `{scan.scan_type}`",
        f"- Status: `{scan.status}`",
        f"- Findings: `{len(findings)}`",
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
        f"<p><strong>Findings:</strong> {len(findings)}</p>{html_findings}</body></html>"
    )
    with open(os.path.join(report_dir, "report.html"), "w", encoding="utf-8") as file:
        file.write(report_html)

    write_json(os.path.join(report_dir, "findings.json"), findings)
    write_json(os.path.join(report_dir, "raw.json"), raw_outputs)
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
        generated_files: dict[str, str] = {}

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
                session.commit()
                continue

            input_file = generated_files.get("subfinder") if tool in {"dnsx", "httpx"} else None
            if tool == "dnsx" and not input_file:
                input_file = os.path.join(report_dir, "target-hosts.txt")
                with open(input_file, "w", encoding="utf-8") as file:
                    file.write(f"{target.host}\n")
            command = build_command(tool, target, input_file=input_file)
            append_log(scan, f"Running whitelisted tool: {tool}")
            session.commit()

            rc, stdout, stderr = run_tool(command, report_dir)
            raw_outputs[tool] = {"returncode": rc, "stdout": stdout, "stderr": stderr}
            log_path = os.path.join(report_dir, f"{tool}.log")
            stdout_path = os.path.join(report_dir, f"{tool}.out")
            with open(log_path, "w", encoding="utf-8") as file:
                file.write(stdout)
                file.write(stderr)
            with open(stdout_path, "w", encoding="utf-8") as file:
                file.write(stdout)
            generated_files[tool] = stdout_path

            if stdout:
                append_log(scan, stdout[-4000:])
            if stderr:
                append_log(scan, stderr[-4000:])
            if rc != 0:
                append_log(scan, f"{tool} exited with code {rc}; continuing with remaining safe steps")
            if tool == "nuclei":
                findings.extend(parse_nuclei_findings(stdout))
            session.commit()

        scan.findings = findings
        scan.summary = f"Scan completed for {target.url}. Findings: {len(findings)}."
        scan.status = "completed"
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
                    f"Target: {target.url}. Scan type: {scan.scan_type}. Findings JSON: {json.dumps(findings[:20], ensure_ascii=False)}"
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

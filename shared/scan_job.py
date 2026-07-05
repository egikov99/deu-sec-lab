import os
import json
import subprocess
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from shared.db import SessionLocal
from shared.models import Scan

REPORTS_ROOT = os.getenv("REPORTS_ROOT", "/reports")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

ALLOWED_COMMANDS = {
    "httpx": ["httpx", "-silent", "-follow-redirects"],
    "katana": ["katana", "-u"],
    "nuclei": ["nuclei", "-t", "-"],
    "subfinder": ["subfinder", "-d"],
    "dnsx": ["dnsx", "-d"],
    "nmap": ["nmap", "-Pn", "-sS"],
}


def validate_target(target: str, allow_private: bool = False) -> str:
    host = target.strip()
    if host.startswith("http://") or host.startswith("https://"):
        return host
    if host.startswith("localhost") and not allow_private:
        raise ValueError("Localhost targets are not allowed")
    if any(host.startswith(prefix) for prefix in ["127.", "10.", "172.", "192."]):
        if not allow_private:
            raise ValueError("Private network targets are not allowed")
        return host
    return host


def run_tool(command: list[str], cwd: str) -> tuple[int, str, str]:
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr


def load_scan_from_db(scan_id: int) -> Session:
    session = SessionLocal()
    return session


def run_scan_task(scan_id: int) -> None:
    session = SessionLocal()
    scan = session.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    report_dir = os.path.join(REPORTS_ROOT, str(scan.project_id), str(scan.id))
    os.makedirs(report_dir, exist_ok=True)
    scan.report_dir = os.path.relpath(report_dir, REPORTS_ROOT)
    scan.status = "running"
    scan.current_step = "Starting scan"
    scan.progress = 5
    scan.started_at = datetime.now(timezone.utc)
    scan.logs = ""
    session.commit()

    try:
        target = validate_target(scan.target, allow_private=os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true")
        steps = [
            {"name": "Validating target", "tool": None},
            {"name": "HTTP probing", "tool": "httpx"},
            {"name": "Katana reconnaissance", "tool": "katana"},
            {"name": "Nuclei scan", "tool": "nuclei"},
        ]
        if scan.scan_type == "extended":
            steps.insert(1, {"name": "Subdomain discovery", "tool": "subfinder"})
            steps.insert(2, {"name": "DNS probing", "tool": "dnsx"})
            steps.append({"name": "Nmap scan", "tool": "nmap"})

        findings: list[dict[str, Any]] = []
        report_files: dict[str, Any] = {}
        raw_outputs: dict[str, Any] = {}

        for index, step in enumerate(steps, start=1):
            scan.current_step = step["name"]
            scan.progress = int((index / len(steps)) * 100)
            session.commit()

            if step["tool"] is None:
                scan.logs += f"[{datetime.now(timezone.utc).isoformat()}] Validating target {target}\n"
                session.commit()
                continue

            command = ALLOWED_COMMANDS[step["tool"]].copy()
            if step["tool"] == "katana":
                command.extend([target, "-H", "User-Agent: DEU-Security-Platform"])
            elif step["tool"] == "httpx":
                command.extend([target, "-status-code", "-title", "-tech-detect"])
            elif step["tool"] == "nuclei":
                command.extend(["-u", target, "-t", "/root/.local/share/nuclei/templates", "-json"])
            elif step["tool"] in {"subfinder", "dnsx"}:
                command.extend(["-d", target])
            elif step["tool"] == "nmap":
                command.extend(["-p", "80,443,8080", target])

            scan.logs += f"[{datetime.now(timezone.utc).isoformat()}] Running {' '.join(command)}\n"
            session.commit()
            rc, stdout, stderr = run_tool(command, REPORTS_ROOT)
            raw_outputs[step["tool"]] = {"returncode": rc, "stdout": stdout, "stderr": stderr}
            with open(os.path.join(report_dir, f"{step['tool']}.log"), "w", encoding="utf-8") as fh:
                fh.write(stdout)
                fh.write(stderr)

            if stdout:
                scan.logs += stdout + "\n"
            if stderr:
                scan.logs += stderr + "\n"
            session.commit()

            if step["tool"] == "nuclei":
                try:
                    results = [json.loads(line) for line in stdout.splitlines() if line.strip()]
                except Exception:
                    results = []
                for item in results:
                    findings.append({
                        "title": item.get("info", {}).get("name", "nuclei finding"),
                        "severity": item.get("info", {}).get("severity", "Medium").capitalize(),
                        "description": item.get("matches", [{}])[0].get("match", "Detected issue"),
                        "recommendation": item.get("info", {}).get("description", "Review this finding"),
                        "evidence": item.get("matched-at", ""),
                        "raw_output": item,
                    })

        summary = f"Scan completed with {len(findings)} findings."
        scan.findings = findings
        scan.summary = summary
        scan.status = "completed"
        scan.logs += f"[{datetime.now(timezone.utc).isoformat()}] Scan finished\n"
        with open(os.path.join(report_dir, "summary.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# Scan summary\n\nTarget: {target}\n\nStatus: completed\n\nFindings: {len(findings)}\n")
        with open(os.path.join(report_dir, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        with open(os.path.join(report_dir, "raw.json"), "w", encoding="utf-8") as fh:
            json.dump(raw_outputs, fh, indent=2)
        with open(os.path.join(report_dir, "logs.txt"), "w", encoding="utf-8") as fh:
            fh.write(scan.logs)

        if os.getenv("OPENAI_API_KEY"):
            try:
                from openai import OpenAI
                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                prompt = f"Generate a brief security summary for target {target} and findings count {len(findings)}."
                response = client.responses.create(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), input=prompt)
                scan.summary = response.output_text or scan.summary
            except Exception:
                pass

        scan.report_dir = os.path.relpath(report_dir, REPORTS_ROOT)
        session.commit()

    except Exception as exc:
        scan.status = "failed"
        scan.logs += f"[{datetime.now(timezone.utc).isoformat()}] Error: {exc}\n"
        session.commit()
    finally:
        session.commit()

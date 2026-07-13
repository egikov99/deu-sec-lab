from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from redis import Redis
from rq import Queue
from sqlalchemy.orm import Session

from shared.db import engine, SessionLocal
from shared.claude_bughunter_runner import ClaudeBugHunterMethodology
from shared.models import Finding, Project, Report, Scan, ScanStep
from shared.schema import ensure_schema
from shared.security_utils import encrypt_json
from shared.target import validate_target

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REPORTS_ROOT = os.getenv("REPORTS_ROOT", "/reports")
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"

ensure_schema()

SCAN_STATUSES = {"queued", "planning", "running", "waiting_approval", "validating", "reporting", "completed", "completed_with_warnings", "failed", "cancelled", "interrupted"}

app = FastAPI(title="DEU Security API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1)
    target: str = Field(min_length=1)
    description: str = ""
    scan_type: str = Field(default="basic", pattern="^(basic|extended)$")
    default_scan_mode: str = Field(default="safe_validation", pattern="^(passive|safe_validation|explicit_approval)$")
    authorization_confirmed: bool = False
    credentials: Optional[dict] = None
    origin_ip: Optional[str] = None
    origin_scan_confirmed: bool = False


class ScanStatusUpdate(BaseModel):
    status: str
    current_step: Optional[str] = None
    progress: Optional[int] = None
    message: Optional[str] = None


class ScanLogPayload(BaseModel):
    message: str


class ScanCompletePayload(BaseModel):
    summary: str
    findings: list[dict]
    report_dir: str
    logs: str
    raw_output: dict


class ReportDownloadRequest(BaseModel):
    filename: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_queue() -> Queue:
    return Queue(connection=Redis.from_url(REDIS_URL), default_timeout=3600)


def report_files(report_dir: str | None) -> list[str]:
    if not report_dir:
        return []
    root = os.path.join(REPORTS_ROOT, report_dir)
    allowed = {"summary.md", "report.md", "report.html", "raw.json", "normalized.json", "metadata.json", "methodology.json", "findings.json", "scan-plan.json", "timeline.json", "logs.txt", "report.pdf", "full-scan.zip"}
    files = [name for name in allowed if os.path.exists(os.path.join(root, name))]
    files.extend(sorted(name for name in os.listdir(root) if name.endswith((".log", ".out"))))
    return sorted(files)


def scan_payload(scan: Scan) -> dict:
    steps = [
        {
            "id": step.id,
            "sequence": step.sequence,
            "phase": step.phase,
            "skill": step.skill,
            "tool": step.tool,
            "input_summary": step.input_summary,
            "status": step.status,
            "started_at": step.started_at.isoformat() if step.started_at else None,
            "finished_at": step.finished_at.isoformat() if step.finished_at else None,
            "ai_analysis": step.ai_analysis or {},
            "next_action": step.next_action or {},
            "error": step.error,
        }
        for step in sorted(scan.steps or [], key=lambda item: item.sequence)
    ]
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "current_step": scan.current_step,
        "progress": scan.progress,
        "scan_type": scan.scan_type,
        "scan_mode": scan.scan_mode,
        "phase": scan.phase,
        "model": scan.model,
        "methodology_commit": scan.methodology_commit,
        "selected_skills": scan.selected_skills or [],
        "checklist": scan.checklist or {},
        "token_usage": scan.token_usage or {},
        "estimated_cost": scan.estimated_cost,
        "approval_requests": scan.approval_requests or [],
        "target": scan.target,
        "logs": scan.logs,
        "summary": scan.summary,
        "findings": scan.findings or [],
        "warnings": scan.warnings or [],
        "tool_status": scan.tool_status or {},
        "normalized_outputs": scan.normalized_outputs or {},
        "scan_metadata": scan.scan_metadata or {},
        "report_dir": scan.report_dir,
        "files": report_files(scan.report_dir),
        "steps": steps,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }


@app.get("/health")
def health():
    return {"status": "ok", "claude_bughunter": ClaudeBugHunterMethodology().readiness()}


@app.get("/api/readiness")
def readiness():
    return ClaudeBugHunterMethodology().readiness()


@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return [
        {
            "id": project.id,
            "name": project.name,
            "target": project.target,
            "description": project.description,
            "scan_type": project.scan_type,
            "default_scan_mode": project.default_scan_mode,
            "authorization_confirmed": bool(project.authorization_confirmed),
            "origin_ip": project.origin_ip,
            "origin_scan_confirmed": bool(project.origin_scan_confirmed),
            "created_at": project.created_at.isoformat(),
        }
        for project in projects
    ]


@app.post("/api/projects", status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    try:
        target = validate_target(payload.target, allow_private=ALLOW_PRIVATE_TARGETS)
        origin_ip = None
        if payload.origin_ip:
            origin = validate_target(payload.origin_ip, allow_private=ALLOW_PRIVATE_TARGETS)
            if not origin.is_ip:
                raise ValueError("origin_ip must be an IP address")
            origin_ip = origin.host
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    project = Project(
        name=payload.name,
        target=target.url,
        description=payload.description,
        scan_type=payload.scan_type,
        default_scan_mode=payload.default_scan_mode,
        authorization_confirmed=payload.authorization_confirmed,
        credentials_encrypted=encrypt_json(payload.credentials),
        origin_ip=origin_ip,
        origin_scan_confirmed=payload.origin_scan_confirmed,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return {
        "id": project.id,
        "name": project.name,
        "target": project.target,
        "description": project.description,
        "scan_type": project.scan_type,
        "default_scan_mode": project.default_scan_mode,
        "authorization_confirmed": bool(project.authorization_confirmed),
        "origin_ip": project.origin_ip,
        "origin_scan_confirmed": bool(project.origin_scan_confirmed),
    }


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    scans = db.query(Scan).filter(Scan.project_id == project.id).order_by(Scan.created_at.desc()).all()
    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "target": project.target,
            "description": project.description,
            "scan_type": project.scan_type,
            "default_scan_mode": project.default_scan_mode,
            "authorization_confirmed": bool(project.authorization_confirmed),
            "origin_ip": project.origin_ip,
            "origin_scan_confirmed": bool(project.origin_scan_confirmed),
            "created_at": project.created_at.isoformat(),
        },
        "latest_scan": None if not scans else scan_payload(scans[0]),
        "scans": [scan_payload(scan) for scan in scans],
    }


@app.post("/api/projects/{project_id}/scan", status_code=201)
def start_scan(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not bool(project.authorization_confirmed):
        raise HTTPException(status_code=400, detail="Authorization confirmation is required before starting a scan")

    scan = Scan(
        project_id=project.id,
        target=project.target,
        scan_type=project.scan_type,
        scan_mode=project.default_scan_mode,
        status="queued",
        phase="queued",
        current_step="Queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    queue = get_queue()
    queue.enqueue("shared.scan_job.run_scan_task", scan.id, job_timeout=1800)
    return {"scan": {"id": scan.id, "status": scan.status, "current_step": scan.current_step, "progress": scan.progress, "scan_type": scan.scan_type}} 


@app.post("/api/scans/{scan_id}/resume", status_code=202)
def resume_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"interrupted", "failed", "waiting_approval"}:
        raise HTTPException(status_code=400, detail="Only interrupted, failed, or waiting approval scans can be resumed")
    scan.status = "queued"
    scan.phase = "queued"
    scan.current_step = "Queued for resume"
    scan.finished_at = None
    db.commit()
    get_queue().enqueue("shared.scan_job.run_scan_task", scan.id, job_timeout=1800)
    return {"ok": True}


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "cancelled"
    scan.phase = "cancelled"
    scan.current_step = "Cancelled"
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_payload(scan)


@app.post("/api/scans/{scan_id}/status")
def update_scan_status(scan_id: int, payload: ScanStatusUpdate, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status not in SCAN_STATUSES:
        raise HTTPException(status_code=400, detail="Unsupported scan status")
    scan.status = payload.status
    scan.current_step = payload.current_step or scan.current_step
    if payload.progress is not None:
        scan.progress = payload.progress
    if payload.message:
        scan.logs = (scan.logs or "") + f"[{datetime.now(timezone.utc).isoformat()}] {payload.message}\n"
    if payload.status == "running" and not scan.started_at:
        scan.started_at = datetime.now(timezone.utc)
    if payload.status in {"completed", "completed_with_warnings", "failed", "cancelled", "interrupted"}:
        scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@app.post("/api/scans/{scan_id}/log")
def append_scan_log(scan_id: int, payload: ScanLogPayload, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.logs = (scan.logs or "") + f"[{datetime.now(timezone.utc).isoformat()}] {payload.message}\n"
    db.commit()
    return {"ok": True}


@app.post("/api/scans/{scan_id}/complete")
def complete_scan(scan_id: int, payload: ScanCompletePayload, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "completed"
    scan.summary = payload.summary
    scan.findings = payload.findings
    scan.report_dir = payload.report_dir
    scan.logs = payload.logs
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@app.get("/api/projects/{project_id}/findings")
def project_findings(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    findings = db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.last_seen_at.desc()).all()
    return [
        {
            "id": item.id,
            "scan_id": item.scan_id,
            "fingerprint": item.fingerprint,
            "title": item.title,
            "severity": item.severity,
            "confidence": item.confidence,
            "category": item.category,
            "endpoint": item.endpoint,
            "parameter": item.parameter,
            "validation_status": item.validation_status,
            "status": item.status,
            "first_seen_at": item.first_seen_at.isoformat(),
            "last_seen_at": item.last_seen_at.isoformat(),
        }
        for item in findings
    ]


@app.get("/api/projects/{project_id}/reports")
def project_reports(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    scans = db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.created_at.desc()).all()
    return [
        {
            "scan_id": scan.id,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "methodology_commit": scan.methodology_commit,
            "files": report_files(scan.report_dir),
        }
        for scan in scans
    ]


@app.post("/api/scans/{scan_id}/fail")
def fail_scan(scan_id: int, payload: ScanLogPayload, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "failed"
    scan.logs = (scan.logs or "") + f"[{datetime.now(timezone.utc).isoformat()}] {payload.message}\n"
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@app.get("/api/reports/{scan_id}")
def get_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report_dir = scan.report_dir or ""
    markdown_path = os.path.join(REPORTS_ROOT, report_dir, "summary.md") if report_dir else ""
    findings_path = os.path.join(REPORTS_ROOT, report_dir, "findings.json") if report_dir else ""
    if markdown_path and os.path.exists(markdown_path):
        with open(markdown_path, "r", encoding="utf-8") as fh:
            markdown = fh.read()
    else:
        markdown = ""
    if findings_path and os.path.exists(findings_path):
        with open(findings_path, "r", encoding="utf-8") as fh:
            findings = json.load(fh)
    else:
        findings = scan.findings or []
    return {
        "scan_id": scan.id,
        "summary": scan.summary,
        "markdown": markdown,
        "findings": findings,
        "warnings": scan.warnings or [],
        "tool_status": scan.tool_status or {},
        "normalized_outputs": scan.normalized_outputs or {},
        "scan_metadata": scan.scan_metadata or {},
        "files": report_files(report_dir),
    }


@app.get("/api/reports/{scan_id}/download/{filename}")
def download_report(scan_id: int, filename: str, db: Session = Depends(get_db)):
    if "/" in filename or "\\" in filename or not filename.endswith((".md", ".html", ".json", ".txt", ".pdf", ".log", ".out")):
        raise HTTPException(status_code=400, detail="Unsupported report file")
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target_path = os.path.join(REPORTS_ROOT, scan.report_dir or "", filename)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return Response(content=open(target_path, "rb").read(), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={filename}"})

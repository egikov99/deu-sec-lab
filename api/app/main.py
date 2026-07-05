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
from shared.models import Project, Scan

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REPORTS_ROOT = os.getenv("REPORTS_ROOT", "/reports")
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"

Project.metadata.create_all(bind=engine)
Scan.metadata.create_all(bind=engine)

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
    scan_type: str = "basic"


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


@app.get("/health")
def health():
    return {"status": "ok"}


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
            "created_at": project.created_at.isoformat(),
        }
        for project in projects
    ]


@app.post("/api/projects", status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(
        name=payload.name,
        target=payload.target,
        description=payload.description,
        scan_type=payload.scan_type,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return {"id": project.id, "name": project.name, "target": project.target, "description": project.description, "scan_type": project.scan_type}


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
            "created_at": project.created_at.isoformat(),
        },
        "latest_scan": None if not scans else {
            "id": scans[0].id,
            "status": scans[0].status,
            "current_step": scans[0].current_step,
            "progress": scans[0].progress,
            "scan_type": scans[0].scan_type,
            "logs": scans[0].logs,
            "summary": scans[0].summary,
            "findings": scans[0].findings or [],
            "report_dir": scans[0].report_dir,
            "created_at": scans[0].created_at.isoformat(),
            "started_at": scans[0].started_at.isoformat() if scans[0].started_at else None,
            "finished_at": scans[0].finished_at.isoformat() if scans[0].finished_at else None,
        },
        "scans": [
            {
                "id": scan.id,
                "status": scan.status,
                "current_step": scan.current_step,
                "progress": scan.progress,
                "scan_type": scan.scan_type,
                "logs": scan.logs,
                "summary": scan.summary,
                "findings": scan.findings or [],
                "report_dir": scan.report_dir,
                "created_at": scan.created_at.isoformat(),
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            }
            for scan in scans
        ],
    }


@app.post("/api/projects/{project_id}/scan", status_code=201)
def start_scan(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    scan = Scan(project_id=project.id, target=project.target, scan_type=project.scan_type, status="queued", current_step="Queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    queue = get_queue()
    queue.enqueue("shared.scan_job.run_scan_task", scan.id, job_timeout=1800)
    return {"scan": {"id": scan.id, "status": scan.status, "current_step": scan.current_step, "progress": scan.progress, "scan_type": scan.scan_type}} 


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "current_step": scan.current_step,
        "progress": scan.progress,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "logs": scan.logs,
        "summary": scan.summary,
        "findings": scan.findings or [],
        "report_dir": scan.report_dir,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }


@app.post("/api/scans/{scan_id}/status")
def update_scan_status(scan_id: int, payload: ScanStatusUpdate, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = payload.status
    scan.current_step = payload.current_step or scan.current_step
    if payload.progress is not None:
        scan.progress = payload.progress
    if payload.message:
        scan.logs = (scan.logs or "") + f"[{datetime.now(timezone.utc).isoformat()}] {payload.message}\n"
    if payload.status == "running" and not scan.started_at:
        scan.started_at = datetime.now(timezone.utc)
    if payload.status in {"completed", "failed"}:
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
    return {"scan_id": scan.id, "summary": scan.summary, "markdown": markdown, "findings": findings}


@app.get("/api/reports/{scan_id}/download/{filename}")
def download_report(scan_id: int, filename: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target_path = os.path.join(REPORTS_ROOT, scan.report_dir or "", filename)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return Response(content=open(target_path, "rb").read(), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename={filename}"})

from datetime import datetime, timezone
from typing import Any, Optional
from sqlalchemy import String, Text, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, default="")
    scan_type: Mapped[str] = mapped_column(String(50), default="basic")
    authorization_confirmed: Mapped[bool] = mapped_column(Integer, default=0)
    default_scan_mode: Mapped[str] = mapped_column(String(50), default="safe_validation")
    credentials_encrypted: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    origin_ip: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    origin_scan_confirmed: Mapped[bool] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="queued")
    current_step: Mapped[Optional[str]] = mapped_column(String(255), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), default="basic")
    scan_mode: Mapped[str] = mapped_column(String(50), default="safe_validation")
    phase: Mapped[str] = mapped_column(String(50), default="queued")
    model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    methodology_commit: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    selected_skills: Mapped[list[str]] = mapped_column(JSON, default=list)
    checklist: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    token_usage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    estimated_cost: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    approval_requests: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    logs: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[Optional[str]] = mapped_column(Text, default="")
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    tool_status: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    normalized_outputs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    scan_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_dir: Mapped[Optional[str]] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    project: Mapped[Project] = relationship(back_populates="scans")
    steps: Mapped[list["ScanStep"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    finding_records: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanStep(Base):
    __tablename__ = "scan_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(String(50), default="running")
    skill: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    input_summary: Mapped[Optional[str]] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(50), default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    stdout_artifact: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stderr_artifact: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    structured_result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ai_analysis: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    next_action: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr_summary: Mapped[Optional[str]] = mapped_column(Text, default="")
    stdout_summary: Mapped[Optional[str]] = mapped_column(Text, default="")
    actual_input_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="steps")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="Info")
    confidence: Mapped[str] = mapped_column(String(50), default="medium")
    category: Mapped[str] = mapped_column(String(100), default="")
    cwe: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    cve: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reproduction_steps: Mapped[list[str]] = mapped_column(JSON, default=list)
    remediation: Mapped[Optional[str]] = mapped_column(Text, default="")
    validation_status: Mapped[str] = mapped_column(String(50), default="unvalidated")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    status: Mapped[str] = mapped_column(String(50), default="open")

    scan: Mapped[Scan] = relationship(back_populates="finding_records")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    scan_step_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_steps.id"), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(50), default="raw")
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan: Mapped[Scan] = relationship(back_populates="artifacts")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(50), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan: Mapped[Scan] = relationship(back_populates="reports")

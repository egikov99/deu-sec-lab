from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from shared.models import Artifact, Finding, Project, Report, Scan, ScanStep
from shared.pipeline_utils import administrative_exposures, classify_nmap_target, detect_cdn, final_status, normalize_katana_output, strip_ansi
from shared.security_utils import redact_secrets
from shared.target import ValidatedTarget, validate_target
from shared.tool_registry import ToolRegistry, normalize_finding_fingerprint

REPORTS_ROOT = os.getenv("REPORTS_ROOT", "/reports")
DEFAULT_METHODOLOGY_ROOT = os.getenv("CLAUDE_BUGHUNTER_PATH", "/opt/methodology/Claude-BugHunter")
DEFAULT_REPO = "https://github.com/elementalsouls/Claude-BugHunter"
SAFE_VALIDATION_MODES = {"passive", "safe_validation", "explicit_approval"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def append_log(scan: Scan, message: str) -> None:
    scan.logs = (scan.logs or "") + f"[{utc_now().isoformat()}] {strip_ansi(message)}\n"


def write_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(redact_secrets(payload), file, indent=2, ensure_ascii=False)


class ClaudeBugHunterMethodology:
    def __init__(self, root: str = DEFAULT_METHODOLOGY_ROOT) -> None:
        self.root = Path(root)
        self.repository = DEFAULT_REPO

    def readiness(self) -> dict[str, Any]:
        exists = self.root.is_dir()
        commit = ""
        ref_type = "missing"
        if exists:
            commit = self._git(["rev-parse", "HEAD"])
            tag = self._git(["describe", "--tags", "--exact-match", "HEAD"])
            ref_type = "tag" if tag else "commit" if commit else "directory"
        files = self.index_files() if exists else []
        required = {
            "skills": any("/skills/" in item["path"] and item["path"].endswith("SKILL.md") for item in files),
            "commands": any("/commands/" in item["path"] and item["path"].endswith(".md") for item in files),
            "workflows": any("workflow" in item["path"].lower() for item in files),
            "reports": any("report" in item["path"].lower() for item in files),
            "patterns": any("pattern" in item["path"].lower() or "vulnerab" in item["path"].lower() for item in files),
            "chains": any("chain" in item["path"].lower() for item in files),
            "validation": any("validat" in item["path"].lower() for item in files),
        }
        return {
            "repository": self.repository,
            "root": str(self.root),
            "exists": exists,
            "commit_sha": commit,
            "ref_type": ref_type,
            "pinned": bool(commit) and ref_type in {"commit", "tag"},
            "required_sections": required,
            "ready": exists and bool(commit) and bool(files),
        }

    def _git(self, args: list[str]) -> str:
        try:
            return subprocess.run(["git", "-C", str(self.root), *args], check=False, capture_output=True, text=True).stdout.strip()
        except OSError:
            return ""

    def index_files(self) -> list[dict[str, Any]]:
        if not self.root.is_dir():
            return []
        records: list[dict[str, Any]] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".yaml", ".yml", ".json"}:
                continue
            relative = path.relative_to(self.root)
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            records.append(
                {
                    "path": f"{self.root.name}/{relative}",
                    "kind": self._kind(relative),
                    "title": self._title(content, relative.name),
                    "excerpt": content[:3000],
                }
            )
            if len(records) >= 80:
                break
        return records

    def _kind(self, relative: Path) -> str:
        text = str(relative).lower()
        if "skills" in relative.parts and relative.name == "SKILL.md":
            return "skill"
        if "commands" in relative.parts:
            return "command"
        if "workflow" in text:
            return "workflow"
        if "report" in text:
            return "report_template"
        if "validat" in text:
            return "validation_methodology"
        if "chain" in text:
            return "chain_template"
        if "pattern" in text or "vulnerab" in text:
            return "vulnerability_pattern"
        return "methodology"

    def _title(self, content: str, fallback: str) -> str:
        for line in content.splitlines():
            if line.startswith("#"):
                return line.lstrip("#").strip()[:120] or fallback
        return fallback

    def select_skills(self, scan_type: str, target: ValidatedTarget, indexed: list[dict[str, Any]]) -> list[dict[str, Any]]:
        skills = [item for item in indexed if item["kind"] == "skill"]
        selected = []
        terms = ["web", "recon", "validation", "report"]
        if scan_type == "extended":
            terms.extend(["subdomain", "api", "crawl", "nuclei"])
        for skill in skills:
            haystack = f"{skill['path']} {skill['title']} {skill['excerpt']}".lower()
            if any(term in haystack for term in terms):
                selected.append(skill)
        return selected[:8] or skills[:5]


class ClaudeBugHunterAgentRunner:
    def __init__(self, session: Session, scan: Scan, report_dir: str) -> None:
        self.session = session
        self.scan = scan
        self.report_dir = report_dir
        self.methodology = ClaudeBugHunterMethodology()
        self.registry = ToolRegistry()
        self.max_iterations = int(os.getenv("AGENT_MAX_ITERATIONS", "12"))
        self.max_seconds = int(os.getenv("AGENT_MAX_SECONDS", "1800"))
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def run(self) -> None:
        os.makedirs(self.report_dir, exist_ok=True)
        self.scan.report_dir = os.path.relpath(self.report_dir, REPORTS_ROOT)
        self.scan.status = "planning"
        self.scan.phase = "planning"
        self.scan.current_step = "Loading Claude-BugHunter methodology"
        self.scan.progress = 3
        self.scan.started_at = self.scan.started_at or utc_now()
        self.scan.model = self.model
        self.scan.logs = self.scan.logs or ""
        self.session.commit()

        target = validate_target(self.scan.target, allow_private=os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true")
        project = self.session.query(Project).filter(Project.id == self.scan.project_id).first()
        if not project or not bool(project.authorization_confirmed):
            raise ValueError("Project authorization confirmation is required before scanning.")

        readiness = self.methodology.readiness()
        indexed = self.methodology.index_files()
        selected_skills = self.methodology.select_skills(self.scan.scan_type, target, indexed)
        prior_context = self._prior_context()
        plan = self._planner(target, project, readiness, indexed, selected_skills, prior_context)
        self.scan.methodology_commit = readiness.get("commit_sha") or "missing"
        self.scan.selected_skills = [item["path"] for item in selected_skills]
        self.scan.checklist = {"generated": plan.get("ordered_steps", []), "completed": [], "skipped": []}
        self.scan.scan_metadata = {
            "methodology_name": "Claude-BugHunter",
            "methodology_repository": DEFAULT_REPO,
            "methodology_commit": readiness.get("commit_sha"),
            "methodology_readiness": readiness,
            "selected_skills": selected_skills,
            "selected_workflows": [item for item in indexed if item["kind"] == "workflow"][:8],
            "tool_registry": self.registry.list_for_prompt(),
            "plan": plan,
            "validation_mode": self.scan.scan_mode,
            "agent_iterations": [],
        }
        append_log(self.scan, f"Claude-BugHunter readiness: {'ready' if readiness.get('ready') else 'not ready'}; commit={readiness.get('commit_sha') or 'missing'}")
        if not readiness.get("ready"):
            self.scan.warnings = sorted(set((self.scan.warnings or []) + ["Claude-BugHunter repository is not ready; scan cannot be considered штатный."]))
        self.session.commit()

        raw_outputs: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        start = time.time()
        completed = []

        for iteration, step in enumerate(plan.get("ordered_steps", [])[: self.max_iterations], start=1):
            if time.time() - start > self.max_seconds:
                self._skip_remaining(plan, completed, "time limit reached")
                break
            if self._cancelled_or_interrupted():
                return

            tool = step.get("tool")
            if not tool:
                completed.append(step.get("id") or step.get("name"))
                continue
            validation = self._policy_gate(step)
            if validation["decision"] == "requires_approval":
                self.scan.status = "waiting_approval"
                self.scan.phase = "waiting_approval"
                self.scan.approval_requests = (self.scan.approval_requests or []) + [validation["request"]]
                append_log(self.scan, f"Waiting for approval: {validation['request']['summary']}")
                self.session.commit()
                return
            if validation["decision"] == "blocked":
                self._record_skipped(step, validation["reason"])
                continue

            self.scan.status = "running"
            self.scan.phase = step.get("phase", "executing")
            self.scan.current_step = step.get("name", tool)
            self.scan.progress = min(90, 10 + int((iteration / max(1, len(plan.get("ordered_steps", [])))) * 75))
            self.session.commit()

            scan_step = self._create_step(iteration, step)
            result = self.registry.execute(tool, step.get("args") or {}, target, self.report_dir)
            artifact_paths = self._write_tool_artifacts(iteration, tool, result)
            result["artifacts"] = artifact_paths
            analysis = self._analyzer(target, step, result)
            scan_step.status = "completed" if result.get("status") in {"completed", "skipped"} else "failed"
            scan_step.finished_at = utc_now()
            scan_step.stdout_artifact = artifact_paths.get("stdout")
            scan_step.stderr_artifact = artifact_paths.get("stderr")
            scan_step.structured_result = redact_secrets(result)
            scan_step.ai_analysis = analysis
            scan_step.next_action = analysis.get("next_recommended_action") or {}
            self.scan.tool_status = {**(self.scan.tool_status or {}), tool: {"status": result.get("status"), "returncode": result.get("returncode")}}
            self.scan.normalized_outputs = self._normalize_outputs(tool, result)
            completed.append(step.get("id") or step.get("name"))
            self.scan.checklist = {**(self.scan.checklist or {}), "completed": completed}
            raw_outputs[f"{iteration:02d}_{tool}"] = result
            findings.extend(self._findings_from_result(tool, result, analysis))
            append_log(self.scan, analysis.get("operational_summary") or f"{tool} completed with status {result.get('status')}")
            self._record_iteration(iteration, step, result, analysis)
            self.session.commit()

        self.scan.status = "reporting"
        self.scan.phase = "reporting"
        self.scan.current_step = "Generating reports"
        self.scan.progress = 95
        self.session.commit()

        normalized_findings = self._store_findings(findings)
        self.scan.findings = normalized_findings
        self.scan.status = final_status(self.scan.tool_status or {}, self.scan.warnings or [])
        if self.scan.status == "completed" and self.scan.warnings:
            self.scan.status = "completed_with_warnings"
        self.scan.phase = "completed"
        self.scan.current_step = "Completed"
        self.scan.progress = 100
        self.scan.finished_at = utc_now()
        self.scan.summary = self._reporter(target, plan, normalized_findings)
        self._write_reports(target, plan, normalized_findings, raw_outputs)
        append_log(self.scan, "Scan finished")
        self.session.commit()

    def _planner(self, target: ValidatedTarget, project: Project, readiness: dict[str, Any], indexed: list[dict[str, Any]], selected_skills: list[dict[str, Any]], prior_context: dict[str, Any]) -> dict[str, Any]:
        base_steps = [
            {"id": "headers", "name": "Check headers and TLS-facing metadata", "phase": "recon", "skill": self._skill_name(selected_skills, "header"), "tool": "header_tls_checker", "args": {"url": target.url}, "validation_level": "passive"},
            {"id": "httpx", "name": "Probe HTTP service", "phase": "recon", "skill": self._skill_name(selected_skills, "recon"), "tool": "httpx", "args": {"url": target.url}, "validation_level": "passive"},
            {"id": "katana", "name": "Crawl target routes", "phase": "coverage", "skill": self._skill_name(selected_skills, "crawl"), "tool": "katana", "args": {"url": target.url}, "validation_level": "passive"},
            {"id": "nuclei", "name": "Run safe nuclei checks", "phase": "detection", "skill": self._skill_name(selected_skills, "vulnerability"), "tool": "nuclei", "args": {"url": target.url}, "validation_level": "safe_validation"},
        ]
        if self.scan.scan_type == "extended" and target.is_domain:
            base_steps.insert(0, {"id": "subfinder", "name": "Discover authorized subdomains", "phase": "recon", "skill": self._skill_name(selected_skills, "subdomain"), "tool": "subfinder", "args": {"domain": target.host}, "validation_level": "passive"})
            base_steps.insert(1, {"id": "dnsx", "name": "Resolve discovered hosts", "phase": "recon", "skill": self._skill_name(selected_skills, "dns"), "tool": "dnsx", "args": {"domain": target.host}, "validation_level": "passive"})
        if self.scan.scan_type == "extended":
            project_origin = project.origin_ip if project.origin_scan_confirmed else target.host
            base_steps.append({"id": "nmap", "name": "Check allowlisted ports", "phase": "exposure", "skill": self._skill_name(selected_skills, "infrastructure"), "tool": "nmap", "args": {"host": project_origin, "ports": os.getenv("NMAP_ALLOWED_PORTS", "80,443,8080,8443")}, "validation_level": "safe_validation"})
        fallback_plan = {
            "objectives": ["Map authorized attack surface", "Run Claude-BugHunter selected safe checks", "Validate findings only with non-destructive evidence", "Generate reports and artifacts"],
            "attack_surface": {"target": target.url, "host": target.host, "scan_type": self.scan.scan_type, "prior_open_findings": prior_context.get("open_findings", [])},
            "selected_skills": [item["path"] for item in selected_skills],
            "ordered_steps": base_steps,
            "required_tools": sorted({step["tool"] for step in base_steps if step.get("tool")}),
            "validation_rules": ["passive by default", "no destructive exploitation", "no brute force", "no persistence", "approval required for explicit validation"],
            "stop_conditions": ["plan complete", "iteration/time limit", "no safe next step", "manual stop", "critical error"],
            "methodology_ready": readiness.get("ready"),
        }
        ai_plan = self._openai_json(
            "planner",
            {
                "target": {"url": target.url, "host": target.host},
                "scope": {"scan_type": self.scan.scan_type, "scan_mode": self.scan.scan_mode},
                "credentials_metadata": {"configured": bool(project.credentials_encrypted), "redacted": True},
                "claude_bughunter_readiness": readiness,
                "claude_bughunter_skills": selected_skills,
                "available_tools": self.registry.list_for_prompt(),
                "previous_results": prior_context,
                "fallback_plan": fallback_plan,
            },
        )
        if ai_plan and self._valid_plan(ai_plan):
            return ai_plan
        return fallback_plan

    def _skill_name(self, skills: list[dict[str, Any]], term: str) -> str:
        for skill in skills:
            if term in f"{skill['path']} {skill['title']}".lower():
                return skill["path"]
        return skills[0]["path"] if skills else "Claude-BugHunter/default"

    def _analyzer(self, target: ValidatedTarget, step: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        status = result.get("status")
        observations = []
        candidates = result.get("findings", [])
        stdout = result.get("stdout") or ""
        if status == "skipped":
            observations.append(f"{step.get('tool')} was skipped: {result.get('reason')}")
        elif status == "failed":
            observations.append(f"{step.get('tool')} failed with return code {result.get('returncode')}")
        elif stdout:
            observations.append(f"{step.get('tool')} returned {len(stdout.splitlines())} output lines")
        else:
            observations.append(f"{step.get('tool')} completed without notable output")
        if step.get("tool") == "header_tls_checker":
            checks = result.get("checks") or {}
            for name, present in checks.items():
                if not present:
                    candidates.append(
                        {
                            "title": f"Missing {name.replace('_', ' ')}",
                            "severity": "Low",
                            "confidence": "medium",
                            "category": "Security Headers",
                            "endpoint": target.url,
                            "evidence": {"header_check": checks},
                            "description": f"The response does not include {name.replace('_', '-')}.",
                            "recommendation": "Review response security headers and add the missing control where appropriate.",
                            "validation_status": "validated",
                        }
                    )
        fallback = {
            "observations": observations,
            "candidate_findings": candidates,
            "confidence": "medium" if candidates else "low",
            "next_recommended_action": {"type": "continue", "reason": "Proceed with the next safe planned step."},
            "validation_needed": bool(candidates),
            "operational_summary": f"{step.get('name')}: {observations[0]}",
        }
        ai_analysis = self._openai_json(
            "analyzer",
            {
                "step": redact_secrets(step),
                "tool_result": redact_secrets({key: value for key, value in result.items() if key not in {"stdout", "stderr"}}),
                "stdout_preview": (result.get("stdout") or "")[-8000:],
                "fallback_analysis": fallback,
            },
        )
        if isinstance(ai_analysis, dict) and isinstance(ai_analysis.get("observations"), list):
            return {**fallback, **ai_analysis}
        return fallback

    def _policy_gate(self, step: dict[str, Any]) -> dict[str, Any]:
        mode = self.scan.scan_mode if self.scan.scan_mode in SAFE_VALIDATION_MODES else "safe_validation"
        level = step.get("validation_level", "passive")
        if level == "passive":
            return {"decision": "allowed"}
        if level == "safe_validation" and mode in {"safe_validation", "explicit_approval"}:
            return {"decision": "allowed"}
        if level == "explicit_approval" and mode == "explicit_approval":
            return {
                "decision": "requires_approval",
                "request": {
                    "summary": step.get("name"),
                    "risk": "Active validation may interact with the target beyond passive observation.",
                    "target": step.get("args", {}).get("url") or step.get("args", {}).get("host"),
                    "endpoint": step.get("args", {}).get("url"),
                    "tool": step.get("tool"),
                    "confirmation_text": "I confirm that I own or am authorized to test this target.",
                },
            }
        return {"decision": "blocked", "reason": f"{level} is not allowed in {mode} mode"}

    def _create_step(self, sequence: int, step: dict[str, Any]) -> ScanStep:
        scan_step = ScanStep(
            scan_id=self.scan.id,
            sequence=sequence,
            phase=step.get("phase", "running"),
            skill=step.get("skill"),
            tool=step.get("tool"),
            input_summary=json.dumps(redact_secrets(step.get("args") or {}), ensure_ascii=False),
            status="running",
            started_at=utc_now(),
        )
        self.session.add(scan_step)
        self.session.commit()
        return scan_step

    def _write_tool_artifacts(self, sequence: int, tool: str, result: dict[str, Any]) -> dict[str, str]:
        paths = {}
        for key in ("stdout", "stderr"):
            value = result.get(key)
            if not value:
                continue
            filename = f"{sequence:02d}-{tool}.{key}.txt"
            full_path = os.path.join(self.report_dir, filename)
            with open(full_path, "w", encoding="utf-8") as file:
                file.write(redact_secrets(value))
            paths[key] = filename
            self._record_artifact(filename, "raw")
        return paths

    def _record_artifact(self, filename: str, artifact_type: str) -> None:
        full_path = os.path.join(self.report_dir, filename)
        size = os.path.getsize(full_path) if os.path.exists(full_path) else 0
        import hashlib

        digest = ""
        if os.path.exists(full_path):
            with open(full_path, "rb") as file:
                digest = hashlib.sha256(file.read()).hexdigest()
        self.session.add(Artifact(scan_id=self.scan.id, type=artifact_type, filename=filename, storage_path=os.path.relpath(full_path, REPORTS_ROOT), sha256=digest, size=size))

    def _normalize_outputs(self, tool: str, result: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(self.scan.normalized_outputs or {})
        if tool == "katana":
            normalized["katana"] = normalize_katana_output(result.get("stdout", ""), self.scan.target)
        if tool == "httpx":
            normalized["administrative_exposure"] = administrative_exposures(result.get("stdout", ""))
        if tool == "nmap":
            project = self.session.query(Project).filter(Project.id == self.scan.project_id).first()
            target = validate_target(self.scan.target, allow_private=os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true")
            cdn = normalized.get("cdn_detection") or detect_cdn(target.host)
            normalized["cdn_detection"] = cdn
            normalized["nmap"] = classify_nmap_target(target.host, cdn, project.origin_ip if project else None, bool(project.origin_scan_confirmed) if project else False)
        return normalized

    def _findings_from_result(self, tool: str, result: dict[str, Any], analysis: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        for item in result.get("findings", []) + analysis.get("candidate_findings", []):
            item = dict(item)
            item.setdefault("category", tool)
            item.setdefault("confidence", analysis.get("confidence", "medium"))
            item.setdefault("validation_status", "validated" if tool in {"nuclei", "header_tls_checker"} else "candidate")
            item.setdefault("endpoint", item.get("technical_details", {}).get("matched_at") or self.scan.target)
            item["fingerprint"] = normalize_finding_fingerprint(item)
            findings.append(item)
        return findings

    def _store_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped = {}
        for finding in findings:
            deduped[finding["fingerprint"]] = finding
        for item in deduped.values():
            self.session.add(
                Finding(
                    project_id=self.scan.project_id,
                    scan_id=self.scan.id,
                    fingerprint=item["fingerprint"],
                    title=item.get("title", "Finding"),
                    severity=item.get("severity", "Info"),
                    confidence=item.get("confidence", "medium"),
                    category=item.get("category", ""),
                    cwe=item.get("cwe") or item.get("CWE"),
                    cve=item.get("cve") or item.get("CVE"),
                    endpoint=item.get("endpoint"),
                    parameter=item.get("parameter"),
                    evidence=item.get("evidence") or item.get("technical_details") or {},
                    reproduction_steps=item.get("reproduction_steps") or [],
                    remediation=item.get("remediation") or item.get("recommendation", ""),
                    validation_status=item.get("validation_status", "unvalidated"),
                    status=item.get("status", "open"),
                )
            )
        self.session.commit()
        return list(deduped.values())

    def _reporter(self, target: ValidatedTarget, plan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        fallback = f"Claude-BugHunter scan completed for {target.url}. Findings: {len(findings)}. Methodology commit: {self.scan.methodology_commit or 'missing'}."
        ai_report = self._openai_json(
            "reporter",
            {
                "target": target.url,
                "plan": plan,
                "findings": findings[:50],
                "methodology": self.scan.scan_metadata,
                "fallback_summary": fallback,
            },
        )
        if isinstance(ai_report, dict) and isinstance(ai_report.get("summary"), str):
            return ai_report["summary"][:5000]
        return fallback

    def _openai_json(self, role: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        if not os.getenv("OPENAI_API_KEY"):
            return None
        prompts = {
            "planner": "Return only JSON for a safe security scan plan. Preserve the schema keys from fallback_plan. Only use tools listed in available_tools. Do not invent shell commands.",
            "analyzer": "Return only JSON with observations, candidate_findings, confidence, next_recommended_action, validation_needed, and operational_summary. Do not include hidden chain-of-thought.",
            "reporter": "Return only JSON with a concise summary string for an internal authorized security report.",
        }
        try:
            from openai import OpenAI

            client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            response = client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": prompts[role]},
                    {"role": "user", "content": json.dumps(redact_secrets(payload), ensure_ascii=False)},
                ],
                temperature=0,
            )
            usage = getattr(response, "usage", None)
            if usage:
                current = dict(self.scan.token_usage or {})
                current[role] = {
                    "prompt_tokens": getattr(usage, "prompt_tokens", None),
                    "completion_tokens": getattr(usage, "completion_tokens", None),
                    "total_tokens": getattr(usage, "total_tokens", None),
                }
                self.scan.token_usage = current
            content = response.choices[0].message.content or "{}"
            return json.loads(content)
        except Exception as exc:
            append_log(self.scan, f"OpenAI {role} JSON step skipped: {exc}")
            return None

    def _valid_plan(self, plan: dict[str, Any]) -> bool:
        if not isinstance(plan.get("ordered_steps"), list):
            return False
        registered = set(self.registry.definitions)
        for step in plan["ordered_steps"]:
            tool = step.get("tool")
            if tool and tool not in registered:
                return False
            if "args" in step and not isinstance(step["args"], dict):
                return False
        return True

    def _write_reports(self, target: ValidatedTarget, plan: dict[str, Any], findings: list[dict[str, Any]], raw_outputs: dict[str, Any]) -> None:
        methodology = self.scan.scan_metadata or {}
        timeline = [
            {
                "sequence": step.sequence,
                "phase": step.phase,
                "tool": step.tool,
                "status": step.status,
                "started_at": step.started_at.isoformat() if step.started_at else None,
                "finished_at": step.finished_at.isoformat() if step.finished_at else None,
                "analysis": step.ai_analysis,
            }
            for step in self.session.query(ScanStep).filter(ScanStep.scan_id == self.scan.id).order_by(ScanStep.sequence.asc()).all()
        ]
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        counts = {severity: sum(1 for item in findings if item.get("severity") == severity) for severity in severity_order}
        md = [
            "# Security scan report",
            "",
            "## Executive summary",
            "",
            self.scan.summary or "",
            "",
            "## Target and scope",
            "",
            f"- Target: `{target.url}`",
            f"- Authorization confirmed: `{True}`",
            f"- Scan mode: `{self.scan.scan_mode}`",
            "",
            "## Methodology",
            "",
            f"- Engine: `Claude-BugHunter`",
            f"- Repository: `{DEFAULT_REPO}`",
            f"- Commit: `{self.scan.methodology_commit or 'missing'}`",
            f"- Used skills: `{', '.join(self.scan.selected_skills or []) or 'none'}`",
            "",
            "## Coverage",
            "",
            f"- Completed steps: `{len((self.scan.checklist or {}).get('completed', []))}`",
            f"- Failed/skipped tools: `{', '.join(name for name, status in (self.scan.tool_status or {}).items() if status.get('status') != 'completed') or 'none'}`",
            "",
            "## Severity summary",
            "",
            *[f"- {severity}: {counts[severity]}" for severity in severity_order],
            "",
            "## Findings",
            "",
        ]
        if findings:
            for finding in findings:
                md.extend(
                    [
                        f"### {finding.get('severity', 'Info')} - {finding.get('title', 'Finding')}",
                        "",
                        finding.get("description", ""),
                        "",
                        f"- Confidence: `{finding.get('confidence', 'medium')}`",
                        f"- Validation: `{finding.get('validation_status', 'unvalidated')}`",
                        f"- Endpoint: `{finding.get('endpoint', 'not recorded')}`",
                        f"- Remediation: {finding.get('remediation') or finding.get('recommendation', '')}",
                        "",
                    ]
                )
        else:
            md.append("No findings were produced by the enabled safe checks.")
        md.extend(["", "## Limitations", "", "- No destructive exploitation, brute force, persistence, data modification, or lateral movement is performed.", "- Riskier validation requires explicit approval."])
        summary_md = "\n".join(md)
        files = {
            "report.md": summary_md,
            "summary.md": summary_md,
            "findings.json": findings,
            "scan-plan.json": plan,
            "methodology.json": methodology,
            "timeline.json": timeline,
            "raw.json": raw_outputs,
            "normalized.json": self.scan.normalized_outputs or {},
            "metadata.json": methodology,
            "logs.txt": self.scan.logs or "",
        }
        for filename, payload in files.items():
            path = os.path.join(self.report_dir, filename)
            if isinstance(payload, str):
                with open(path, "w", encoding="utf-8") as file:
                    file.write(redact_secrets(payload))
            else:
                write_json(path, payload)
            self._record_artifact(filename, "report" if filename.startswith("report") else "artifact")
        html_findings = "".join(f"<section><h3>{html.escape(item.get('severity', 'Info'))}: {html.escape(item.get('title', 'Finding'))}</h3><p>{html.escape(item.get('description', ''))}</p></section>" for item in findings) or "<p>No findings.</p>"
        html_path = os.path.join(self.report_dir, "report.html")
        with open(html_path, "w", encoding="utf-8") as file:
            file.write(f"<!doctype html><html><head><meta charset='utf-8'><title>Security report</title><style>body{{font-family:Arial,sans-serif;margin:32px;line-height:1.5}}section{{border-top:1px solid #ddd;padding:12px 0}}</style></head><body><h1>Security scan report</h1><p><strong>Target:</strong> {html.escape(target.url)}</p><p><strong>Claude-BugHunter commit:</strong> {html.escape(self.scan.methodology_commit or 'missing')}</p>{html_findings}</body></html>")
        self._record_artifact("report.html", "report")
        zip_path = os.path.join(self.report_dir, "full-scan.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in Path(self.report_dir).iterdir():
                if path.name != "full-scan.zip" and path.is_file():
                    archive.write(path, arcname=path.name)
        self._record_artifact("full-scan.zip", "report")
        for filename in ("report.html", "report.md", "findings.json", "scan-plan.json", "methodology.json", "timeline.json", "full-scan.zip"):
            self.session.add(Report(scan_id=self.scan.id, format=filename.rsplit(".", 1)[-1], filename=filename))
        self.session.commit()

    def _prior_context(self) -> dict[str, Any]:
        previous = (
            self.session.query(Scan)
            .filter(Scan.project_id == self.scan.project_id, Scan.id != self.scan.id)
            .order_by(Scan.created_at.desc())
            .limit(5)
            .all()
        )
        return {
            "recent_scans": [{"id": item.id, "status": item.status, "finding_count": len(item.findings or [])} for item in previous],
            "open_findings": [finding.fingerprint for finding in self.session.query(Finding).filter(Finding.project_id == self.scan.project_id, Finding.status == "open").limit(20).all()],
        }

    def _record_iteration(self, iteration: int, step: dict[str, Any], result: dict[str, Any], analysis: dict[str, Any]) -> None:
        metadata = dict(self.scan.scan_metadata or {})
        metadata["agent_iterations"] = (metadata.get("agent_iterations") or []) + [
            {
                "iteration": iteration,
                "tool": step.get("tool"),
                "skill": step.get("skill"),
                "status": result.get("status"),
                "validation_decision": self._policy_gate(step).get("decision"),
                "analysis_summary": analysis.get("operational_summary"),
            }
        ]
        self.scan.scan_metadata = metadata

    def _record_skipped(self, step: dict[str, Any], reason: str) -> None:
        checklist = dict(self.scan.checklist or {})
        checklist["skipped"] = (checklist.get("skipped") or []) + [{"step": step.get("id") or step.get("name"), "reason": reason}]
        self.scan.checklist = checklist
        append_log(self.scan, f"Skipped {step.get('name')}: {reason}")
        self.session.commit()

    def _skip_remaining(self, plan: dict[str, Any], completed: list[str], reason: str) -> None:
        skipped = []
        for step in plan.get("ordered_steps", []):
            step_id = step.get("id") or step.get("name")
            if step_id not in completed:
                skipped.append({"step": step_id, "reason": reason})
        checklist = dict(self.scan.checklist or {})
        checklist["skipped"] = (checklist.get("skipped") or []) + skipped
        self.scan.checklist = checklist

    def _cancelled_or_interrupted(self) -> bool:
        self.session.refresh(self.scan)
        if self.scan.status == "cancelled":
            self.scan.phase = "cancelled"
            self.scan.finished_at = utc_now()
            self.session.commit()
            return True
        return False

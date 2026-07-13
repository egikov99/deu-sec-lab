import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared.claude_bughunter_runner import ClaudeBugHunterAgentRunner, ClaudeBugHunterMethodology
from shared.models import Base, Project, Scan, ScanStep
from shared.target import validate_target
from shared.tool_registry import DnsxArgs, HttpxArgs, NmapArgs, ToolError, ToolRegistry


def make_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def make_runner(tmp_path, scan_mode="safe_validation"):
    session = make_session()
    project = Project(
        name="Example",
        target="https://example.com",
        description="",
        scan_type="extended",
        authorization_confirmed=True,
        default_scan_mode=scan_mode,
    )
    session.add(project)
    session.commit()
    scan = Scan(project_id=project.id, target=project.target, scan_type="extended", scan_mode=scan_mode, status="queued")
    session.add(scan)
    session.commit()
    runner = ClaudeBugHunterAgentRunner(session, scan, str(tmp_path / "reports"))
    runner.methodology = ClaudeBugHunterMethodology(str(tmp_path / "missing-Claude-BugHunter"))
    return session, project, scan, runner


def test_full_scan_blocked_when_claude_readiness_false(tmp_path):
    session, _, scan, runner = make_runner(tmp_path)
    runner.run()
    session.refresh(scan)
    assert scan.status == "blocked"
    assert scan.methodology_commit == "missing"
    assert "Claude-BugHunter methodology is not available" in scan.summary
    assert scan.scan_metadata["methodology_blocker"]["exists"] is False


def test_dnsx_skipped_on_empty_discovered_hosts(tmp_path):
    target = validate_target("https://example.com")
    registry = ToolRegistry()
    result = registry._execute_process("dnsx", DnsxArgs(hosts=[]), target, str(tmp_path), registry.definitions["dnsx"])
    assert result["status"] == "skipped"
    assert result["failure_category"] == "empty_input"
    assert result["actual_input_count"] == 0


def test_httpx_receives_original_target_fallback(tmp_path):
    target = validate_target("https://example.com")
    registry = ToolRegistry()
    prepared = registry._prepare_command("httpx", HttpxArgs(targets=[]), target, str(tmp_path))
    assert prepared["actual_input_count"] == 1
    assert prepared["normalized_arguments"]["targets"] == ["https://example.com"]


def test_url_converted_to_hostname_for_nmap(tmp_path):
    target = validate_target("https://example.com")
    registry = ToolRegistry()
    prepared = registry._prepare_command("nmap", NmapArgs(host="https://example.com/path", ports=[80, 443]), target, str(tmp_path))
    assert prepared["normalized_arguments"]["host"] == "example.com"
    assert prepared["normalized_arguments"]["ports"] == "80,443"


def test_nmap_skipped_behind_cdn_without_origin_ip(tmp_path):
    session, project, scan, runner = make_runner(tmp_path, scan_mode="fallback")
    target = validate_target("https://example.com")
    scan.normalized_outputs = {"cdn_detection": {"is_cdn": True, "providers": ["Cloudflare"]}}
    step = {"id": "nmap", "tool": "nmap", "args": {"host": "example.com"}}
    prepared = runner._prepare_dependency_step(step, {"target_host": "example.com"}, project, target)
    assert prepared["skip_before_execution"] is True
    assert prepared["failure_category"] == "policy_blocked"


def test_host_none_rejected_before_execution():
    registry = ToolRegistry()
    try:
        registry.validate_call("nmap", {"host": None})
    except ToolError as exc:
        assert "Invalid arguments" in str(exc)
    else:
        raise AssertionError("host=None should be rejected")


def test_invalid_tool_args_do_not_crash_scan_step(tmp_path):
    session, _, scan, runner = make_runner(tmp_path, scan_mode="fallback")
    step = ScanStep(scan_id=scan.id, sequence=1, phase="exposure", tool="nmap", status="running")
    session.add(step)
    session.commit()
    result = runner._invalid_tool_result("nmap", {"host": None}, ToolError("host is required"))
    runner._finish_step(step, result, {"operational_summary": "invalid args", "observations": ["invalid args"]})
    session.commit()
    session.refresh(step)
    assert step.status == "skipped"
    assert step.failure_category == "invalid_arguments"
    assert "host is required" in step.stderr_summary


def test_history_persists_failed_or_skipped_steps(tmp_path):
    session, _, scan, runner = make_runner(tmp_path, scan_mode="fallback")
    runner._record_synthetic_step(1, {"id": "dnsx", "tool": "dnsx", "name": "Resolve"}, "skipped", "No discovered hosts to resolve", "empty_input")
    stored = session.query(ScanStep).filter(ScanStep.scan_id == scan.id).one()
    assert stored.status == "skipped"
    assert stored.failure_category == "empty_input"
    assert stored.error == "No discovered hosts to resolve"

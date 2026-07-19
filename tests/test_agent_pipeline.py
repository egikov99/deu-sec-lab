import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared.claude_bughunter_runner import ClaudeBugHunterAgentRunner, ClaudeBugHunterMethodology
from shared.models import Base, Project, Scan, ScanStep
from shared.target import validate_target
from shared.tool_registry import DnsxArgs, HttpxArgs, NmapArgs, ToolError, ToolRegistry, failure_category, parse_httpx_json_lines, unique_http_targets


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
    assert prepared["stdin"] == "https://example.com\n"
    assert "-json" in prepared["command"]
    assert prepared["command"][0].endswith("/httpx")


def test_projectdiscovery_httpx_binary_detection_is_required():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "worker" / "Dockerfile").read_text()
    entrypoint = (root / "worker" / "entrypoint.sh").read_text()
    module = "github.com/projectdiscovery/httpx/cmd/httpx"
    assert module in dockerfile
    assert module in entrypoint
    assert "httpx -version" in dockerfile
    assert "httpx -version" in entrypoint


def test_httpx_url_normalization_and_deduplication():
    targets = unique_http_targets([" https://Example.com/path?q=1#frag ", "https://example.com/path?q=1", "example.org", None, "bad host"], "")
    assert targets == ["https://example.com/path?q=1", "example.org"]


def test_project_target_with_path_is_valid_and_fragment_removed():
    target = validate_target("https://example.com/path?q=1#section")
    assert target.url == "https://example.com/path?q=1"


def test_partial_httpx_json_is_retained_with_warning():
    parsed, warnings = parse_httpx_json_lines('{"url":"https://example.com"}\nnot-json\n')
    assert parsed == [{"url": "https://example.com"}]
    assert len(warnings) == 1


def test_retry_categories_are_limited_to_transient_failures():
    assert failure_category(1, "", "temporary failure in name resolution") == "dns_temporary"
    assert failure_category(1, "", "connection reset by peer") == "connection_reset"
    assert failure_category(1, "", "unknown flag: -json") == "invalid_arguments"


def test_httpx_stderr_exit_code_and_no_shell(monkeypatch, tmp_path):
    popen_calls = []
    class Process:
        returncode = 1
        def communicate(self, input=None, timeout=None):
            self.input = input
            return "", "unknown flag: -json"
    def popen(command, **kwargs):
        popen_calls.append((command, kwargs))
        return Process()
    monkeypatch.setattr("shared.tool_registry.shutil.which", lambda value: value)
    monkeypatch.setattr("shared.tool_registry.subprocess.Popen", popen)
    result = ToolRegistry()._run(["/usr/local/bin/httpx", "-json"], str(tmp_path), 10, 1000, retry_count=2, input_text="https://example.com\n")
    assert result["exit_code"] == 1
    assert result["stderr"] == "unknown flag: -json"
    assert result["failure_category"] == "invalid_arguments"
    assert len(popen_calls) == 1
    assert "shell" not in popen_calls[0][1]


def test_temporary_failure_retries(monkeypatch, tmp_path):
    attempts = iter([(1, "temporary failure in name resolution"), (0, "")])
    class Process:
        def __init__(self):
            self.returncode, self.stderr = next(attempts)
        def communicate(self, input=None, timeout=None):
            return "{}\n" if self.returncode == 0 else "", self.stderr
    monkeypatch.setattr("shared.tool_registry.shutil.which", lambda value: value)
    monkeypatch.setattr("shared.tool_registry.subprocess.Popen", lambda *args, **kwargs: Process())
    result = ToolRegistry()._run(["httpx"], str(tmp_path), 10, 1000, retry_count=1, input_text="example.com\n")
    assert result["status"] == "completed"
    assert result["retry_count"] == 1


def test_fallback_head_then_get(monkeypatch):
    calls = []
    class Response:
        def __init__(self, code):
            self.status_code = code
            self.url = "https://example.com"
        def close(self):
            pass
    def request(method, *args, **kwargs):
        calls.append((method, kwargs))
        return Response(405 if method == "HEAD" else 200)
    monkeypatch.setattr("shared.tool_registry.requests.request", request)
    result = ToolRegistry().safe_http_reachability("https://example.com", timeout=3)
    assert result["reachable"] is True
    assert result["method"] == "GET"
    assert [item[0] for item in calls] == ["HEAD", "GET"]
    assert all(item[1]["stream"] is True for item in calls)


def test_katana_and_nuclei_continue_with_fallback_target(tmp_path):
    _, project, _, runner = make_runner(tmp_path)
    target = validate_target("https://example.com")
    state = {"reachable_targets": ["https://example.com"], "target_url": "https://example.com"}
    for tool in ("katana", "nuclei"):
        prepared = runner._prepare_dependency_step({"id": tool, "tool": tool, "args": {}}, state, project, target)
        assert not prepared.get("skip_before_execution")
        assert prepared["args"]["url"] == "https://example.com"


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

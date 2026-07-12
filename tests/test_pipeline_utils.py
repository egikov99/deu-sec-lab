from pathlib import Path

from shared.pipeline_utils import (
    NUCLEI_WARNING,
    classify_nmap_target,
    detect_cdn,
    ensure_nuclei_templates,
    final_status,
    has_nuclei_templates,
    methodology_metadata,
    normalize_katana_output,
    strip_ansi,
    tool_outcome,
)


def test_missing_nuclei_templates(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    assert not has_nuclei_templates(templates)


def test_automatic_nuclei_template_initialization(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()

    def fake_run(command, cwd):
        if command == ["nuclei", "-update-templates"]:
            (templates / "http" / "example.yaml").parent.mkdir()
            (templates / "http" / "example.yaml").write_text("id: example\ninfo:\n  name: example\n", encoding="utf-8")
        return 0, "\x1b[32mok\x1b[0m", ""

    ok, status = ensure_nuclei_templates(fake_run, str(tmp_path), str(templates))
    assert ok
    assert status["initialized"]
    assert status["validated"]
    assert status["validate_returncode"] == 0


def test_completed_with_warnings_for_failed_nuclei():
    tools = {"httpx": tool_outcome("httpx", 0), "nuclei": tool_outcome("nuclei", 1)}
    assert final_status(tools, [NUCLEI_WARNING]) == "completed_with_warnings"


def test_cloudflare_cdn_detection_from_ip():
    result = detect_cdn("yudilen-strusto.by", ["172.67.191.119"])
    assert result["is_cdn"]
    assert "Cloudflare" in result["providers"]


def test_nmap_edge_classification_for_cdn_without_origin():
    cdn = {"is_cdn": True, "providers": ["Cloudflare"], "resolved_ips": ["172.67.191.119"]}
    result = classify_nmap_target("yudilen-strusto.by", cdn, None, False)
    assert result["scope"] == "public_edge_exposure"
    assert result["edge_scan"] is True
    assert "origin server" in result["warning"]


def test_nmap_origin_classification_requires_explicit_confirmation():
    cdn = {"is_cdn": True, "providers": ["Cloudflare"], "resolved_ips": ["172.67.191.119"]}
    result = classify_nmap_target("example.com", cdn, "203.0.113.10", True)
    assert result["scope"] == "origin_infrastructure_exposure"
    assert result["target"] == "203.0.113.10"
    assert result["edge_scan"] is False


def test_katana_deduplicates_and_classifies_routes():
    output = "\n".join(
        [
            "https://example.com/login",
            "/login",
            "https://example.com/_next/static/chunks/app.js",
            "trusto.by/_next/static/chunks/bad.js",
            "https://example.com/logo.png",
            "https://cdn.example.net/lib.js",
            "/api/users",
            "/privacy",
        ]
    )
    normalized = normalize_katana_output(output, "https://example.com")
    assert normalized["authentication_endpoints"] == ["https://example.com/login"]
    assert "https://example.com/privacy" in normalized["pages"]
    assert "https://example.com/api/users" in normalized["api_endpoints"]
    assert "https://example.com/logo.png" in normalized["static_assets"]
    assert "https://example.com/_next/static/chunks/app.js" in normalized["javascript"]
    assert "https://example.com/trusto.by/_next/static/chunks/bad.js" in normalized["javascript"]
    assert "https://cdn.example.net/lib.js" in normalized["external_domains"]
    assert "https://example.com/login" in normalized["significant_routes"]
    assert "https://example.com/privacy" in normalized["significant_routes"]


def test_ansi_stripping():
    assert strip_ansi("\x1b[31mfailed\x1b[0m") == "failed"


def test_failed_tool_reporting():
    status = {"nuclei": tool_outcome("nuclei", 1), "nmap": tool_outcome("nmap", 0)}
    assert status["nuclei"]["status"] == "failed"
    assert final_status(status, []) == "completed_with_warnings"


def test_methodology_metadata_records_files(tmp_path):
    root = tmp_path / "Claude-BugHunter"
    root.mkdir()
    (root / "workflow.md").write_text("# workflow\n", encoding="utf-8")
    metadata = methodology_metadata(str(root), "extended")
    assert metadata["methodology_name"] == "Claude-BugHunter"
    assert metadata["workflow"] == "web-application-safe-recon"
    assert str(root / "workflow.md") in metadata["methodology_files"]
    assert metadata["checklist"]

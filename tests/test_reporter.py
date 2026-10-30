"""Tests for core/reporter.py: Reporter.write() produces structurally
consistent markdown/JSON/SARIF outputs from one shared findings fixture."""

import json
import os

from core.reporter import Reporter


def _sample_findings():
    return [
        {
            "type": "xss",
            "normalized_type": "xss",
            "module": "xss",
            "cwe": "CWE-79",
            "severity": "high",
            "endpoint": "http://test.local/search?q=1",
            "payload": "<script>",
            "evidence": "reflected payload",
            "confidence": 0.85,
            "risk_score": 80,
            "risk_rating": "high",
            "risk": "High likelihood of compromise or data exposure.",
            "mitigation": "Escape output.",
            "references": "https://owasp.org/",
            "vulnerability_point": "http://test.local/search?q=1",
            "target_response": {
                "status_code": 200,
                "content_type": "text/html",
                "server": "nginx",
                "content_length": 123,
            },
            "lab_validation": "Reproduce on a local vulnerable app page.",
        }
    ]


def _run_context():
    return {
        "target_type": "web_app",
        "targets": ["http://test.local/"],
        "selected_modules": ["xss"],
        "test_plan": {},
        "exploitation_policy": "Detect on target, validate exploitability only in controlled lab",
        "lab_environment": "local-lab",
        "output_formats": ["markdown", "json", "sarif"],
    }


def test_write_creates_expected_files_for_all_formats(tmp_path, utils):
    reporter = Reporter(output_base=str(tmp_path))
    outputs = reporter.write(_run_context(), [], _sample_findings(), utils)

    assert os.path.exists(outputs["markdown"])
    assert os.path.exists(outputs["findings_json"])
    assert os.path.exists(outputs["sarif"])
    assert os.path.exists(outputs["context_json"])
    assert os.path.exists(outputs["endpoints_json"])
    assert os.path.exists(outputs["session_json"])


def test_write_markdown_contains_finding_details(tmp_path, utils):
    reporter = Reporter(output_base=str(tmp_path))
    outputs = reporter.write(_run_context(), [], _sample_findings(), utils)

    content = open(outputs["markdown"], encoding="utf-8").read()
    assert "XSS (HIGH)" in content
    assert "CWE-79" in content
    assert "reflected payload" in content


def test_write_findings_json_matches_input_findings(tmp_path, utils):
    reporter = Reporter(output_base=str(tmp_path))
    findings = _sample_findings()
    outputs = reporter.write(_run_context(), [], findings, utils)

    with open(outputs["findings_json"], encoding="utf-8") as f:
        data = json.load(f)
    assert data == findings


def test_write_sarif_structure_has_one_rule_and_one_result(tmp_path, utils):
    reporter = Reporter(output_base=str(tmp_path))
    outputs = reporter.write(_run_context(), [], _sample_findings(), utils)

    with open(outputs["sarif"], encoding="utf-8") as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "xss"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"


def test_write_without_markdown_format_skips_report_md(tmp_path, utils):
    reporter = Reporter(output_base=str(tmp_path))
    context = _run_context()
    context["output_formats"] = ["json"]
    outputs = reporter.write(context, [], _sample_findings(), utils)

    assert "markdown" not in outputs
    assert not os.path.exists(os.path.join(outputs["run_path"], "report.md"))


def test_write_empty_findings_notes_no_findings_in_markdown(tmp_path, utils):
    reporter = Reporter(output_base=str(tmp_path))
    outputs = reporter.write(_run_context(), [], [], utils)

    content = open(outputs["markdown"], encoding="utf-8").read()
    assert "No findings detected in this run." in content

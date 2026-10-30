"""Tests for core/diff_scan.py: differential (before/after) scan comparison."""

from core.diff_scan import compare_findings, finding_key


def test_finding_key_prefers_normalized_type_over_type():
    finding = {"normalized_type": "FILE_INCLUSION_INDICATOR", "type": "file inclusion", "endpoint": "http://a/", "payload": "p"}
    assert finding_key(finding) == ("file_inclusion_indicator", "http://a/", "p")


def test_finding_key_falls_back_to_type_when_normalized_type_absent():
    finding = {"type": "XSS", "endpoint": "http://a/", "payload": "p"}
    assert finding_key(finding) == ("xss", "http://a/", "p")


def test_finding_key_defaults_missing_fields():
    assert finding_key({}) == ("unknown", "", "N/A")


def test_compare_findings_identifies_new_resolved_and_persisting():
    baseline = [
        {"type": "xss", "endpoint": "http://a/", "payload": "p1"},
        {"type": "sqli", "endpoint": "http://a/", "payload": "p2"},
    ]
    current = [
        {"type": "sqli", "endpoint": "http://a/", "payload": "p2"},
        {"type": "idor", "endpoint": "http://b/", "payload": "p3"},
    ]

    result = compare_findings(baseline, current)

    assert result["baseline_count"] == 2
    assert result["current_count"] == 2
    assert result["new_count"] == 1
    assert result["resolved_count"] == 1
    assert result["persisting_count"] == 1
    assert result["new_findings"][0]["type"] == "idor"
    assert result["resolved_findings"][0]["type"] == "xss"
    assert result["persisting_findings"][0]["type"] == "sqli"


def test_compare_findings_empty_baseline_all_current_are_new():
    current = [{"type": "xss", "endpoint": "http://a/", "payload": "p"}]
    result = compare_findings([], current)

    assert result["new_count"] == 1
    assert result["resolved_count"] == 0
    assert result["persisting_count"] == 0


def test_compare_findings_empty_current_all_baseline_are_resolved():
    baseline = [{"type": "xss", "endpoint": "http://a/", "payload": "p"}]
    result = compare_findings(baseline, [])

    assert result["new_count"] == 0
    assert result["resolved_count"] == 1
    assert result["persisting_count"] == 0

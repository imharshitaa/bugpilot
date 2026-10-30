"""Tests for core/validator.py: finding deduplication and evidence trimming."""

from core.validator import Validator


def test_deduplicate_removes_exact_type_endpoint_payload_duplicates():
    validator = Validator()
    findings = [
        {"type": "xss", "endpoint": "http://a/", "payload": "<x>", "evidence": "first"},
        {"type": "xss", "endpoint": "http://a/", "payload": "<x>", "evidence": "duplicate"},
        {"type": "xss", "endpoint": "http://a/", "payload": "<y>", "evidence": "different payload"},
    ]

    result = validator.deduplicate(findings)

    assert len(result) == 2
    assert result[0]["evidence"] == "first"
    assert result[1]["payload"] == "<y>"


def test_deduplicate_preserves_first_occurrence_order():
    validator = Validator()
    findings = [
        {"type": "sqli", "endpoint": "http://a/", "payload": "1"},
        {"type": "xss", "endpoint": "http://b/", "payload": "2"},
        {"type": "sqli", "endpoint": "http://a/", "payload": "1"},
    ]

    result = validator.deduplicate(findings)

    assert [f["type"] for f in result] == ["sqli", "xss"]


def test_deduplicate_treats_missing_fields_as_defaults():
    validator = Validator()
    findings = [{"evidence": "no type/endpoint/payload keys"}, {"evidence": "another"}]

    result = validator.deduplicate(findings)

    assert len(result) == 1


def test_trim_evidence_leaves_short_text_unchanged():
    validator = Validator()
    text = "short evidence"
    assert validator.trim_evidence(text) == text


def test_trim_evidence_truncates_long_text_with_ellipsis():
    validator = Validator()
    text = "a" * 400
    trimmed = validator.trim_evidence(text)

    assert trimmed == "a" * 300 + "..."
    assert len(trimmed) == 303


def test_trim_evidence_boundary_exactly_300_chars_unchanged():
    validator = Validator()
    text = "a" * 300
    assert validator.trim_evidence(text) == text

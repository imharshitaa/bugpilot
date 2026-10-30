"""Tests for core/risk_scorer.py: RiskScorer.score()'s exact weighted formula.

score = severity_base*0.6 + clamped_confidence*100*0.25
        + min(len(evidence)/300, 1.0)*100*0.15 + (10 if sensitive endpoint else 0)
rounded, clamped to [0, 100]. Ratings: >=85 critical, >=70 high, >=45 medium, else low.
"""

from core.risk_scorer import RiskScorer


def test_high_confidence_admin_endpoint_scores_95_critical():
    scorer = RiskScorer()
    finding = {
        "severity": "high",
        "confidence": 1.0,
        "evidence": "x" * 300,
        "endpoint": "https://test.local/admin/users",
    }

    result = scorer.score(finding)

    assert result["risk_score"] == 95
    assert result["risk_rating"] == "critical"


def test_medium_severity_with_default_confidence_lands_exactly_on_medium_boundary():
    scorer = RiskScorer()
    finding = {"severity": "medium", "evidence": "", "endpoint": "https://test.local/page"}

    result = scorer.score(finding)

    assert result["risk_score"] == 45
    assert result["risk_rating"] == "medium"


def test_low_severity_zero_confidence_scores_low():
    scorer = RiskScorer()
    finding = {
        "severity": "low",
        "confidence": 0.0,
        "evidence": "",
        "endpoint": "https://test.local/page",
    }

    result = scorer.score(finding)

    assert result["risk_score"] == 15
    assert result["risk_rating"] == "low"


def test_confidence_above_one_is_clamped_to_one():
    scorer = RiskScorer()
    finding = {
        "severity": "low",
        "confidence": 5,
        "evidence": "",
        "endpoint": "https://test.local/page",
    }

    result = scorer.score(finding)

    assert result["risk_score"] == 40
    assert result["risk_rating"] == "low"


def test_invalid_confidence_falls_back_to_default_point_six():
    scorer = RiskScorer()
    finding = {
        "severity": "low",
        "confidence": "not-a-number",
        "evidence": "",
        "endpoint": "https://test.local/page",
    }

    result = scorer.score(finding)

    assert result["risk_score"] == 30


def test_unknown_severity_defaults_to_low_base():
    scorer = RiskScorer()
    finding = {
        "severity": "nonsense",
        "confidence": 0.0,
        "evidence": "",
        "endpoint": "https://test.local/page",
    }

    result = scorer.score(finding)

    assert result["risk_score"] == 15
    assert result["risk_rating"] == "low"


def test_sensitive_endpoint_keyword_adds_ten_point_boost():
    scorer = RiskScorer()
    base_finding = {"severity": "low", "confidence": 0.0, "evidence": ""}

    plain = scorer.score({**base_finding, "endpoint": "https://test.local/page"})
    sensitive = scorer.score({**base_finding, "endpoint": "https://test.local/account/settings"})

    assert sensitive["risk_score"] - plain["risk_score"] == 10


def test_score_never_exceeds_100_or_drops_below_0():
    scorer = RiskScorer()
    finding = {
        "severity": "critical",
        "confidence": 1.0,
        "evidence": "x" * 1000,
        "endpoint": "https://test.local/admin",
    }

    result = scorer.score(finding)

    assert 0 <= result["risk_score"] <= 100

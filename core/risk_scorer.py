"""Risk scoring for findings."""


class RiskScorer:
    SEVERITY_BASE = {
        "critical": 90,
        "high": 75,
        "medium": 50,
        "low": 25,
    }

    RISK_TEXT = {
        "critical": "Immediate exploitation risk with likely high business impact.",
        "high": "High likelihood of compromise or data exposure.",
        "medium": "Moderate exploitability; can be chained for larger impact.",
        "low": "Low direct impact but can weaken overall security posture.",
    }

    def _keyword_boost(self, endpoint):
        value = str(endpoint or "").lower()
        keywords = ["admin", "auth", "login", "payment", "billing", "account"]
        return 10 if any(k in value for k in keywords) else 0

    def score(self, finding):
        severity = str(finding.get("severity", "low")).lower()
        base = self.SEVERITY_BASE.get(severity, 25)

        confidence = finding.get("confidence", 0.6)
        try:
            confidence = float(confidence)
        except Exception:
            confidence = 0.6
        confidence = max(0.0, min(confidence, 1.0))

        evidence_len = len(str(finding.get("evidence", "")))
        evidence_factor = min(evidence_len / 300.0, 1.0)
        endpoint_boost = self._keyword_boost(finding.get("endpoint"))

        score = (base * 0.6) + (confidence * 100 * 0.25) + (evidence_factor * 100 * 0.15) + endpoint_boost
        score = int(round(max(0, min(score, 100))))

        if score >= 85:
            rating = "critical"
        elif score >= 70:
            rating = "high"
        elif score >= 45:
            rating = "medium"
        else:
            rating = "low"

        return {
            "risk_score": score,
            "risk_rating": rating,
            "risk": self.RISK_TEXT[rating],
        }

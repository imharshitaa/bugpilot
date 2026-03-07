"""
ssrf.py
--------
SSRF indicator checks with baseline-aware signal validation.
"""

from core.detection_engine import DetectionEngine
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["ssrf"]
    engine = DetectionEngine(utils)

    for ep in endpoints:
        baseline_resp = utils.http_request(ep.url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in rules["payloads"]:
            test_urls = engine.build_test_urls(
                ep.url,
                payload,
                preferred_params=["url", "redirect", "next", "dest", "callback"],
            )
            for test_url in test_urls:
                resp = utils.http_request(test_url)
                if not resp:
                    continue

                if not engine.has_new_indicator(
                    baseline_text,
                    resp.text,
                    rules["match_indicators"],
                ):
                    continue

                evidence = resp.text[:220]
                if engine.likely_false_positive(evidence):
                    continue

                confidence = 0.75
                if resp.status_code >= 500:
                    confidence = 0.85

                findings.append(
                    {
                        "type": "server side request forgery",
                        "cwe": "CWE-918",
                        "severity": get_severity("ssrf"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": confidence,
                        "mitigation": MITIGATIONS["ssrf"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["ssrf"]),
                        "references": REFERENCES["ssrf"],
                    }
                )
                break

    return findings

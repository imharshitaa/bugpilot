"""
xss.py
-------
Reflected XSS detection with baseline-aware reflection validation.
"""

from core.detection_engine import DetectionEngine
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["xss"]
    engine = DetectionEngine(utils)

    for ep in endpoints:
        baseline_resp = utils.http_request(ep.url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in rules["payloads"]:
            test_urls = engine.build_test_urls(
                ep.url,
                payload,
                preferred_params=["q", "search", "query", "test", "input"],
            )

            for test_url in test_urls:
                resp = utils.http_request(test_url)
                if not resp:
                    continue

                if not engine.reflected_unescaped(payload, resp.text):
                    continue

                if payload in baseline_text:
                    continue

                evidence = resp.text[:220]
                if engine.likely_false_positive(evidence):
                    continue

                confidence = 0.75
                if engine.status_or_body_changed(baseline_resp, resp):
                    confidence = 0.85

                findings.append(
                    {
                        "type": "xss",
                        "cwe": "CWE-79",
                        "severity": get_severity("xss"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": confidence,
                        "mitigation": MITIGATIONS["xss"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["xss"]),
                        "references": REFERENCES["xss"],
                    }
                )
                break

    return findings

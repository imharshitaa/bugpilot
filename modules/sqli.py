"""
sqli.py
--------
Error-based SQLi indicator detection with baseline comparison.
"""

from core.detection_engine import DetectionEngine
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["sqli"]
    engine = DetectionEngine(utils)

    for ep in endpoints:
        baseline_resp = utils.http_request(ep.url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in rules["payloads"]:
            test_urls = engine.build_test_urls(ep.url, payload, preferred_params=["id", "uid", "item", "q"])
            for test_url in test_urls:
                resp = utils.http_request(test_url)
                if not resp:
                    continue

                if not engine.has_new_indicator(
                    baseline_text,
                    resp.text,
                    rules["error_signatures"],
                ):
                    continue

                evidence = resp.text[:240]
                if engine.likely_false_positive(evidence):
                    continue

                if not engine.status_or_body_changed(baseline_resp, resp):
                    continue

                findings.append(
                    {
                        "type": "sqli",
                        "cwe": "CWE-89",
                        "severity": get_severity("sqli"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": 0.9,
                        "mitigation": MITIGATIONS["sqli"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["sqli"]),
                        "references": REFERENCES["sqli"],
                    }
                )
                break

    return findings

"""
path_traversal.py
--------------------
Directory traversal indicators with baseline-aware validation.
"""

from core.detection_engine import DetectionEngine
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity

PAYLOADS = [
    "../../etc/passwd",
    "../" * 5 + "etc/passwd",
    "..%2F..%2Fetc/passwd",
]

ERROR_SIGS = ["root:x:", "No such file", "File not found", "failed to open"]


def run(endpoints, utils, payload_rules):
    findings = []
    engine = DetectionEngine(utils)

    for ep in endpoints:
        baseline_resp = utils.http_request(ep.url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in PAYLOADS:
            test_urls = engine.build_test_urls(ep.url, payload, preferred_params=["file", "path", "filename"])
            for test_url in test_urls:
                resp = utils.http_request(test_url)
                if not resp:
                    continue

                if not engine.has_new_indicator(baseline_text, resp.text, ERROR_SIGS):
                    continue

                evidence = resp.text[:220]
                if engine.likely_false_positive(evidence):
                    continue

                findings.append(
                    {
                        "type": "path_traversal",
                        "cwe": "CWE-22",
                        "severity": get_severity("path_traversal"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": 0.85,
                        "mitigation": MITIGATIONS["path_traversal"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["path_traversal"]),
                        "references": REFERENCES["path_traversal"],
                    }
                )
                break

    return findings

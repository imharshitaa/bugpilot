"""
file_inclusion_indicator.py
-----------------------------
LFI/RFI-style indicators with baseline comparison.
"""

from core.detection_engine import DetectionEngine
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity

PAYLOADS = [
    "/etc/passwd",
    "file://etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

ERROR_SIGS = [
    "failed to open stream",
    "No such file or directory",
    "Warning: include",
    "Warning: require",
]


def run(endpoints, utils, payload_rules):
    findings = []
    engine = DetectionEngine(utils)

    for ep in endpoints:
        baseline_resp = utils.http_request(ep.url)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in PAYLOADS:
            test_urls = engine.build_test_urls(ep.url, payload, preferred_params=["file", "page", "include"])
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
                        "type": "file_inclusion_indicator",
                        "cwe": "CWE-98",
                        "severity": get_severity("file_inclusion_indicator"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": 0.85,
                        "mitigation": MITIGATIONS["file_inclusion_indicator"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["file_inclusion_indicator"]),
                        "references": REFERENCES["file_inclusion_indicator"],
                    }
                )
                break

    return findings

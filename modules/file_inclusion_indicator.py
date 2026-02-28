"""
file_inclusion_indicator.py
-----------------------------
Detects LFI/RFI-style error responses.

HOW IT WORKS:
1. Use safe file payloads (no real file fetching)
2. Look for error signatures or stack traces
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES

PAYLOADS = [
    "/etc/passwd",
    "file://etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php"
]

ERROR_SIGS = [
    "failed to open stream",
    "No such file or directory",
    "Warning: include",
    "Warning: require"
]

def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        for payload in PAYLOADS:
            test_url = utils.add_query_params(ep.url, {"file": payload})

            resp = utils.http_request(test_url)
            if not resp:
                continue

            text = resp.text.lower()

            for sig in ERROR_SIGS:
                if sig.lower() in text:
                    findings.append({
                        "type": "file_inclusion_indicator",
                        "cwe": "CWE-98",
                        "severity": get_severity("file_inclusion_indicator"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": resp.text[:200],
                        "mitigation": MITIGATIONS["file_inclusion_indicator"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["file_inclusion_indicator"]),
                        "references": REFERENCES["file_inclusion_indicator"],
                    })
                    break

    return findings

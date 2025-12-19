"""
path_traversal.py
--------------------
Detect directory traversal indicators.

HOW IT WORKS:
1. Append payloads like ../../etc/passwd (safe, non-real)
2. Detect responses that show file read errors / exceptions
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES

PAYLOADS = [
    "../../etc/passwd",
    "../" * 5 + "etc/passwd",
    "..%2F..%2Fetc/passwd"
]

ERROR_SIGS = [
    "root:x:",
    "No such file",
    "File not found",
    "failed to open"
]

def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        for payload in PAYLOADS:

            if "?" in ep.url:
                test_url = f"{ep.url}&file={payload}"
            else:
                test_url = f"{ep.url}?file={payload}"

            resp = utils.http_request(test_url)
            if not resp:
                continue

            text = resp.text.lower()

            for sig in ERROR_SIGS:
                if sig.lower() in text:
                    findings.append({
                        "type": "path_traversal",
                        "cwe": "CWE-22",
                        "severity": "high",
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": resp.text[:200],
                        "mitigation": "Validate file paths and use allowlists.",
                        "exploitation_methods": "\n- Read restricted files (safe detection)\n- Probe directory structure",
                        "references": "https://owasp.org/www-community/attacks/Path_Traversal"
                    })
                    break

    return findings

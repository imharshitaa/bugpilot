"""
misconfig.py
-------------
Detect common security misconfigurations via headers.

HOW IT WORKS:
1. GET each endpoint
2. Check required security headers
3. If missing → report misconfiguration
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES

def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["misconfig"]

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        for header in rules["headers_to_check"]:
            if header not in resp.headers:

                findings.append({
                    "type": "misconfig",
                    "cwe": "CWE-16",
                    "severity": get_severity("misconfig"),
                    "endpoint": ep.url,
                    "payload": "N/A",
                    "evidence": f"Missing header: {header}",
                    "mitigation": MITIGATIONS["misconfig"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["misconfig"]),
                    "references": REFERENCES["misconfig"]
                })

    return findings


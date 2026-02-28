"""
auth_bypass.py
----------------
Detects missing authentication on protected endpoints.

HOW IT WORKS:
1. For each endpoint, remove auth header and send request
2. If response returns a success page → potential auth bypass
3. No exploitation — just detection of access control issues
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES
from models.false_positive import is_false_positive

def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["auth_bypass"]

    # Disable auth for detection
    original_auth = utils.auth_header
    utils.auth_header = None

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        text = resp.text.lower()

        # Identify if sensitive page is accessible without auth
        for indicator in rules["unauth_indicators"]:
            if indicator.lower() in text:
                
                evidence = resp.text[:200]

                if is_false_positive(evidence):
                    continue

                findings.append({
                    "type": "auth_bypass",
                    "cwe": "CWE-284",
                    "severity": get_severity("auth_bypass"),
                    "endpoint": ep.url,
                    "payload": "N/A",
                    "evidence": evidence,
                    "mitigation": MITIGATIONS["auth_bypass"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["auth_bypass"]),
                    "references": REFERENCES["auth_bypass"]
                })
                break

    # Restore original authentication
    utils.auth_header = original_auth

    return findings

"""
open_redirect.py
-------------------
Detects open redirect vulnerabilities.

HOW IT WORKS:
1. Appends redirect_url parameters with safe external link
2. If endpoint redirects to attacker-controlled domain → vulnerability
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES

def run(endpoints, utils, payload_rules):
    findings = []

    test_redirect = "https://example.org"

    for ep in endpoints:
        test_url = utils.add_query_params(ep.url, {"redirect": test_redirect})

        resp = utils.http_request(test_url)
        if not resp:
            continue

        # Check for server redirect to external site
        if resp.history:
            final = resp.url
            if "example.org" in final:
                findings.append({
                    "type": "open_redirect",
                    "cwe": "CWE-601",
                    "severity": get_severity("open_redirect"),
                    "endpoint": ep.url,
                    "payload": test_redirect,
                    "evidence": f"Redirected to {final}",
                    "mitigation": MITIGATIONS["open_redirect"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["open_redirect"]),
                    "references": REFERENCES["open_redirect"],
                })

    return findings

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

    test_redirect = "https://google.com"

    for ep in endpoints:
        url = ep.url

        # Attach redirect parameter safely
        if "?" in url:
            test_url = f"{url}&redirect={test_redirect}"
        else:
            test_url = f"{url}?redirect={test_redirect}"

        resp = utils.http_request(test_url)
        if not resp:
            continue

        # Check for server redirect to external site
        if resp.history:
            final = resp.url
            if "google.com" in final:
                findings.append({
                    "type": "open_redirect",
                    "cwe": "CWE-601",
                    "severity": "medium",
                    "endpoint": ep.url,
                    "payload": test_redirect,
                    "evidence": f"Redirected to {final}",
                    "mitigation": "Validate redirect URLs against an allowlist.",
                    "exploitation_methods": "\n- Phishing redirection\n- Login-page redirection",
                    "references": "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"
                })

    return findings

"""
csrf.py
-------------------
Detects missing anti-CSRF tokens.

HOW IT WORKS:
1. Analyze HTML forms
2. Detect missing CSRF token fields
"""

from bs4 import BeautifulSoup
from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES

def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            if not form.find("input", {"name": "csrf_token"}):
                findings.append({
                    "type": "csrf",
                    "cwe": "CWE-352",
                    "severity": get_severity("csrf"),
                    "endpoint": ep.url,
                    "payload": "N/A",
                    "evidence": "Missing CSRF token in form",
                    "mitigation": MITIGATIONS["csrf"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["csrf"]),
                    "references": REFERENCES["csrf"],
                })

    return findings

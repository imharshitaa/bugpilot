"""
idor.py
---------
Detects Insecure Direct Object Reference.

HOW IT WORKS:
1. Finds numeric or ID parameters in URLs.
2. Increments/changes the ID safely (non-destructive).
3. If response changes in a meaningful way → potential IDOR.
"""

import re
from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES

def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        url = ep.url

        # Identify simple numeric ID parameters ?id=123 or /123
        match = re.search(r'(\d{1,6})', url)
        if not match:
            continue

        original_id = match.group(1)
        test_id = str(int(original_id) + 1)

        test_url = url.replace(original_id, test_id)

        resp_original = utils.http_request(url)
        resp_test = utils.http_request(test_url)

        if not resp_original or not resp_test:
            continue

        # If HTTP 200 OK and different content → IDOR indicator
        if resp_test.status_code == 200 and resp_original.text != resp_test.text:
            findings.append({
                "type": "idor",
                "cwe": "CWE-639",
                "severity": "high",
                "endpoint": ep.url,
                "payload": f"ID changed from {original_id} to {test_id}",
                "evidence": resp_test.text[:200],
                "mitigation": MITIGATIONS["auth_bypass"],
                "exploitation_methods": "\n- Modify IDs in parameters\n- Direct object enumeration",
                "references": "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
            })

    return findings

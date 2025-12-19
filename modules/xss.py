"""
xss.py
-------
Reflected XSS detection using SAFE reflection tests.

HOW IT WORKS:
1. Load XSS payloads from payload_rules.yaml
2. Inject payloads into query parameters
3. Send request to endpoint
4. Check if payload appears in the response (reflection)
5. If reflected → potential XSS indicator
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES
from models.false_positive import is_false_positive

def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["xss"]

    for ep in endpoints:
        for payload in rules["payloads"]:
            
            # Build URL with payload in query string
            test_url = ep.url
            if "?" in test_url:
                test_url = f"{test_url}&test={payload}"
            else:
                test_url = f"{test_url}?test={payload}"

            resp = utils.http_request(test_url)
            if not resp:
                continue

            # Reflection detection (safe)
            if payload in resp.text:
                
                evidence = resp.text[:200]

                if is_false_positive(evidence):
                    continue

                findings.append({
                    "type": "xss",
                    "cwe": "CWE-79",
                    "severity": get_severity("xss"),
                    "endpoint": ep.url,
                    "payload": payload,
                    "evidence": evidence,
                    "mitigation": MITIGATIONS["xss"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["xss"]),
                    "references": REFERENCES["xss"]
                })

    return findings

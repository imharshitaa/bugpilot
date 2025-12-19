"""
sqli.py
--------
Error-based SQL Injection indicator detection.

HOW IT WORKS:
1. Append simple harmless SQLi payloads to parameters
2. Look for error signatures in response (from payload_rules)
3. If matched → possible SQLi indication
4. Does NOT exploit — only detects error behavior
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES
from models.false_positive import is_false_positive

def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["sqli"]

    for ep in endpoints:
        for payload in rules["payloads"]:

            # Build test URL safely
            test_url = ep.url
            if "?" in test_url:
                test_url = f"{test_url}&id={payload}"
            else:
                test_url = f"{test_url}?id={payload}"

            resp = utils.http_request(test_url)
            if not resp:
                continue

            text = resp.text.lower()

            # Look for harmless error indicators
            for signature in rules["error_signatures"]:
                if signature.lower() in text:
                    
                    evidence = resp.text[:200]

                    if is_false_positive(evidence):
                        continue

                    findings.append({
                        "type": "sqli",
                        "cwe": "CWE-89",
                        "severity": get_severity("sqli"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "mitigation": MITIGATIONS["sqli"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["sqli"]),
                        "references": REFERENCES["sqli"]
                    })
                    break

    return findings

"""
ssrf.py
--------
SSRF detection by sending SAFE internal hostname probes.

HOW IT WORKS:
1. Append internal-only URLs to parameters (localhost only)
2. Detect if server tries to fetch them (based on error messages)
3. Absolutely NO exploitation or external callback usage
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES
from models.false_positive import is_false_positive

def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules["ssrf"]

    for ep in endpoints:
        for payload in rules["payloads"]:

            test_url = ep.url
            if "?" in test_url:
                test_url = f"{test_url}&url={payload}"
            else:
                test_url = f"{test_url}?url={payload}"

            resp = utils.http_request(test_url)
            if not resp:
                continue

            text = resp.text.lower()

            for indicator in rules["match_indicators"]:
                if indicator.lower() in text:

                    evidence = resp.text[:200]

                    if is_false_positive(evidence):
                        continue

                    findings.append({
                        "type": "server side request forgery",
                        "cwe": "CWE-918",
                        "severity": get_severity("ssrf"),
                        "endpoint": ep.url,
                        "payload": payload,
                        "evidence": evidence,
                        "mitigation": MITIGATIONS["ssrf"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["ssrf"]),
                        "references": REFERENCES["ssrf"]
                    })
                    break

    return findings

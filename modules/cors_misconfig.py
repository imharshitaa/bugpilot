"""
cors_misconfig.py
---------------------
Detects weak or insecure CORS policies.

HOW IT WORKS:
1. Send request with an untrusted Origin header
2. If ACAO is '*' or reflects attacker origin → vulnerability
"""

from models.severity import get_severity
from models.prompts import MITIGATIONS, EXPLOIT_METHODS, REFERENCES


def run(endpoints, utils, payload_rules):
    findings = []
    attacker_origin = "https://evil.example"

    for ep in endpoints:
        resp = utils.http_request(ep.url, extra_headers={"Origin": attacker_origin})
        if not resp:
            continue

        origin = resp.headers.get("Access-Control-Allow-Origin")
        allow_creds = resp.headers.get("Access-Control-Allow-Credentials")

        if origin == "*" or origin == attacker_origin:
            findings.append({
                "type": "cors_misconfig",
                "cwe": "CWE-942",
                "severity": get_severity("cors_misconfig"),
                "endpoint": ep.url,
                "payload": "N/A",
                "evidence": (
                    f"ACAO={origin}, ACAC={allow_creds}, supplied_origin={attacker_origin}"
                ),
                "mitigation": MITIGATIONS["cors_misconfig"],
                "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["cors_misconfig"]),
                "references": REFERENCES["cors_misconfig"],
            })

    return findings

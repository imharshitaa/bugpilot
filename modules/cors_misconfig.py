"""
cors_misconfig.py
---------------------
Detects actionable CORS misconfiguration patterns.
"""

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    attacker_origin = "https://evil.example"

    for ep in endpoints:
        resp = utils.http_request(ep.url, extra_headers={"Origin": attacker_origin})
        if not resp:
            continue

        origin = (resp.headers.get("Access-Control-Allow-Origin") or "").strip()
        allow_creds = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()

        reflected_origin = origin == attacker_origin
        wildcard_with_creds = origin == "*" and allow_creds == "true"

        # Reduce false positives: only report clearly exploitable or risky combinations.
        if reflected_origin or wildcard_with_creds:
            confidence = 0.85 if reflected_origin else 0.75
            findings.append(
                {
                    "type": "cors_misconfig",
                    "cwe": "CWE-942",
                    "severity": get_severity("cors_misconfig"),
                    "endpoint": ep.url,
                    "payload": "Origin: https://evil.example",
                    "evidence": f"ACAO={origin}, ACAC={allow_creds}, supplied_origin={attacker_origin}",
                    "confidence": confidence,
                    "mitigation": MITIGATIONS["cors_misconfig"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["cors_misconfig"]),
                    "references": REFERENCES["cors_misconfig"],
                }
            )

    return findings

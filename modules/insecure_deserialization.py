"""Insecure deserialization indicator checks."""

from models.false_positive import is_false_positive
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules.get("insecure_deserialization", {})
    payloads = rules.get("payload_markers", [])
    signatures = rules.get("error_signatures", [])

    for ep in endpoints:
        for payload in payloads:
            test_url = utils.add_query_params(ep.url, {"data": payload})
            resp = utils.http_request(test_url)
            if not resp:
                continue

            body = resp.text.lower()
            if not any(sig.lower() in body for sig in signatures):
                continue

            evidence = resp.text[:220]
            if is_false_positive(evidence):
                continue

            findings.append(
                {
                    "type": "insecure_deserialization",
                    "cwe": "CWE-502",
                    "severity": get_severity("insecure_deserialization"),
                    "endpoint": ep.url,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": 0.6,
                    "mitigation": MITIGATIONS["insecure_deserialization"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["insecure_deserialization"]),
                    "references": REFERENCES["insecure_deserialization"],
                }
            )
            break

    return findings

"""XXE indicator checks via safe XML parser probes."""

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules.get("xxe", {})
    payload = rules.get("payload", "")
    signatures = [v.lower() for v in rules.get("error_signatures", [])]

    if not payload:
        return findings

    for ep in endpoints:
        resp = utils.http_request(
            ep.url,
            method="POST",
            payload=payload,
            extra_headers={"Content-Type": "application/xml"},
        )
        if not resp:
            continue

        body = resp.text.lower()
        if any(sig in body for sig in signatures):
            findings.append(
                {
                    "type": "xxe",
                    "cwe": "CWE-611",
                    "severity": get_severity("xxe"),
                    "endpoint": ep.url,
                    "payload": "XML entity probe",
                    "evidence": resp.text[:220],
                    "mitigation": MITIGATIONS["xxe"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["xxe"]),
                    "references": REFERENCES["xxe"],
                }
            )

    return findings

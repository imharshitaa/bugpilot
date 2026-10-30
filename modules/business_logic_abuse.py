"""Business logic abuse indicators via safe parameter tampering."""

from models.false_positive import is_false_positive
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules.get("business_logic_abuse", {})
    tamper_params = rules.get("tamper_params", {})
    success_statuses = set(rules.get("success_statuses", [200]))

    for ep in endpoints:
        for key, value in tamper_params.items():
            test_url = utils.add_query_params(ep.url, {key: value})
            resp = utils.http_request(test_url)
            if not resp:
                continue

            if resp.status_code not in success_statuses or str(value) not in resp.text:
                continue

            evidence = f"Tampered business value accepted with status {resp.status_code}."
            if is_false_positive(evidence):
                continue

            findings.append(
                {
                    "type": "business_logic_abuse",
                    "cwe": "CWE-840",
                    "severity": get_severity("business_logic_abuse"),
                    "endpoint": ep.url,
                    "payload": f"{key}={value}",
                    "evidence": evidence,
                    "confidence": 0.5,
                    "mitigation": MITIGATIONS["business_logic_abuse"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["business_logic_abuse"]),
                    "references": REFERENCES["business_logic_abuse"],
                }
            )
            break

    return findings

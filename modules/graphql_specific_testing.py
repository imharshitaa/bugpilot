"""GraphQL-specific exposure and introspection checks."""

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules.get("graphql_specific_testing", {})
    query = rules.get("introspection_query", '{"query":"{__schema{types{name}}}"}')
    indicators = [v.lower() for v in rules.get("indicators", ["__schema", "graphql"])]

    for ep in endpoints:
        looks_graphql = "graphql" in ep.url.lower()

        if not looks_graphql:
            probe = utils.http_request(ep.url)
            if probe and "graphql" in probe.text.lower():
                looks_graphql = True

        if not looks_graphql:
            continue

        resp = utils.http_request(
            ep.url,
            method="POST",
            payload=query,
            extra_headers={"Content-Type": "application/json"},
        )
        if not resp:
            continue

        body = resp.text.lower()
        if any(ind in body for ind in indicators):
            findings.append(
                {
                    "type": "graphql_specific_testing",
                    "cwe": "CWE-200",
                    "severity": get_severity("graphql_specific_testing"),
                    "endpoint": ep.url,
                    "payload": query,
                    "evidence": resp.text[:220],
                    "mitigation": MITIGATIONS["graphql_specific_testing"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["graphql_specific_testing"]),
                    "references": REFERENCES["graphql_specific_testing"],
                }
            )

    return findings

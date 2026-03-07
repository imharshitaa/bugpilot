"""Rate limiting / brute-force resistance checks (safe, non-destructive)."""

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules.get("rate_limit_bruteforce", {})
    burst_count = int(rules.get("burst_count", 8))
    success_statuses = set(rules.get("success_statuses", [200]))

    for ep in endpoints:
        success_hits = 0
        throttled_hits = 0

        for _ in range(burst_count):
            resp = utils.http_request(ep.url)
            if not resp:
                continue
            if resp.status_code in success_statuses:
                success_hits += 1
            if resp.status_code == 429:
                throttled_hits += 1

        if success_hits >= max(burst_count - 1, 5) and throttled_hits == 0:
            findings.append(
                {
                    "type": "rate_limit_bruteforce",
                    "cwe": "CWE-307",
                    "severity": get_severity("rate_limit_bruteforce"),
                    "endpoint": ep.url,
                    "payload": f"{burst_count} rapid GET requests",
                    "evidence": f"{success_hits}/{burst_count} successful responses with no throttling.",
                    "mitigation": MITIGATIONS["rate_limit_bruteforce"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["rate_limit_bruteforce"]),
                    "references": REFERENCES["rate_limit_bruteforce"],
                }
            )

    return findings

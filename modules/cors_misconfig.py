"""
cors_misconfig.py
---------------------
Detects weak or insecure CORS policies.

HOW IT WORKS:
1. Check Access-Control-Allow-Origin
2. '*' or reflection → vulnerability
"""

from models.severity import get_severity

def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        origin = resp.headers.get("Access-Control-Allow-Origin")
        methods = resp.headers.get("Access-Control-Allow-Methods")

        if origin == "*" or origin == resp.request.url:
            findings.append({
                "type": "cors_misconfig",
                "cwe": "CWE-942",
                "severity": "medium",
                "endpoint": ep.url,
                "payload": "N/A",
                "evidence": f"Access-Control-Allow-Origin: {origin}",
                "mitigation": "Avoid '*' and use strict CORS origins.",
                "exploitation_methods": "\n- Cross-site API data theft\n- Unauthorized JS access",
                "references": "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
            })

    return findings

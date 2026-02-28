"""JWT validation weakness indicators."""

import base64
import json

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def _decode_jwt_header(token):
    try:
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (-len(header_b64) % 4)
        raw = base64.urlsafe_b64decode(header_b64.encode("utf-8"))
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def run(endpoints, utils, payload_rules):
    findings = []
    rules = payload_rules.get("jwt_validation_weaknesses", {})
    weak_algs = {str(v).lower() for v in rules.get("weak_algorithms", ["none"])}

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        auth_header = resp.headers.get("Authorization", "")
        set_cookie = resp.headers.get("Set-Cookie", "")
        text = f"{auth_header}\n{set_cookie}\n{resp.text}"

        tokens = [part for part in text.split() if part.count(".") == 2 and part.startswith("eyJ")]
        for token in tokens[:3]:
            header = _decode_jwt_header(token)
            alg = str(header.get("alg", "")).lower()
            if alg in weak_algs:
                findings.append(
                    {
                        "type": "jwt_validation_weaknesses",
                        "cwe": "CWE-347",
                        "severity": get_severity("jwt_validation_weaknesses"),
                        "endpoint": ep.url,
                        "payload": token[:25] + "...",
                        "evidence": f"JWT header algorithm appears weak: alg={alg}",
                        "mitigation": MITIGATIONS["jwt_validation_weaknesses"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["jwt_validation_weaknesses"]),
                        "references": REFERENCES["jwt_validation_weaknesses"],
                    }
                )
                break

    return findings

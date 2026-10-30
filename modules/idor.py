"""
idor.py
---------
Detects Insecure Direct Object Reference.

HOW IT WORKS:
1. Finds a numeric id in the URL's path or query string (never the host or
   port, to avoid corrupting unrelated digits in the domain/port).
2. Increments it by one (non-destructive).
3. If the response is 200 OK and meaningfully different from the baseline
   -> potential IDOR indicator.

LIMITATIONS: "200 + different body" is a weak heuristic on its own -- many
applications legitimately return different content per id without an
authorization flaw. This is reported as a moderate-confidence indicator
requiring manual verification, not a confirmed vulnerability.
"""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from models.false_positive import is_false_positive
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity

_ID_PATTERN = re.compile(r"(?<![0-9])(\d{1,6})(?![0-9])")


def _build_test_url(url):
    """Return (test_url, original_id, test_id) by mutating a numeric id in
    the URL's path or query value only -- never netloc (host/port)."""
    split = urlsplit(url)

    path_match = _ID_PATTERN.search(split.path)
    if path_match:
        original_id = path_match.group(1)
        test_id = str(int(original_id) + 1)
        new_path = split.path[: path_match.start()] + test_id + split.path[path_match.end():]
        test_url = urlunsplit((split.scheme, split.netloc, new_path, split.query, split.fragment))
        return test_url, original_id, test_id

    query_pairs = parse_qsl(split.query, keep_blank_values=True)
    for idx, (key, value) in enumerate(query_pairs):
        match = _ID_PATTERN.fullmatch(value)
        if match:
            original_id = match.group(1)
            test_id = str(int(original_id) + 1)
            query_pairs[idx] = (key, test_id)
            new_query = urlencode(query_pairs, doseq=True)
            test_url = urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))
            return test_url, original_id, test_id

    return None, None, None


def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        url = ep.url
        test_url, original_id, test_id = _build_test_url(url)
        if not test_url:
            continue

        resp_original = utils.http_request(url)
        if not resp_original or resp_original.status_code != 200:
            continue

        resp_test = utils.http_request(test_url)
        if not resp_test:
            continue

        if resp_test.status_code == 200 and resp_original.text != resp_test.text:
            evidence = resp_test.text[:200]
            if is_false_positive(evidence):
                continue

            findings.append(
                {
                    "type": "idor",
                    "cwe": "CWE-639",
                    "severity": get_severity("idor"),
                    "endpoint": ep.url,
                    "payload": f"ID changed from {original_id} to {test_id}",
                    "evidence": evidence,
                    "confidence": 0.5,
                    "mitigation": MITIGATIONS["idor"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["idor"]),
                    "references": REFERENCES["idor"],
                }
            )

    return findings

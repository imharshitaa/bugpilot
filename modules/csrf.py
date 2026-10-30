"""
csrf.py
-------------------
Detects missing anti-CSRF tokens.

HOW IT WORKS:
1. Analyze HTML forms that submit via POST (GET forms don't need CSRF
   tokens, since they shouldn't carry state-changing side effects).
2. Check for a field name matching one of several common CSRF token
   conventions (not just a single hardcoded "csrf_token" name).

LIMITATIONS: this only inspects the static HTML form markup returned by a
GET request. It cannot see header-based tokens (e.g. custom anti-CSRF
headers checked server-side), cookie-based double-submit schemes, or
SPA/AJAX flows that attach tokens via JavaScript rather than a hidden form
field -- those will not be flagged, and absence of a recognized field name
is treated as a moderate-confidence indicator, not proof.
"""

from bs4 import BeautifulSoup

from models.false_positive import is_false_positive
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity

CSRF_FIELD_NAMES = {
    "csrf_token",
    "_csrf",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__requestverificationtoken",
    "csrf-token",
    "xsrf_token",
    "_token",
}


def _has_csrf_field(form):
    for field in form.find_all(["input", "textarea"]):
        name = (field.get("name") or "").strip().lower()
        if name in CSRF_FIELD_NAMES:
            return True
    return False


def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            method = (form.get("method") or "get").strip().lower()
            if method != "post":
                continue

            if _has_csrf_field(form):
                continue

            evidence = "POST form has no recognized anti-forgery hidden field"
            if is_false_positive(evidence):
                continue

            findings.append(
                {
                    "type": "csrf",
                    "cwe": "CWE-352",
                    "severity": get_severity("csrf"),
                    "endpoint": ep.url,
                    "payload": "N/A",
                    "evidence": evidence,
                    "confidence": 0.55,
                    "mitigation": MITIGATIONS["csrf"],
                    "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["csrf"]),
                    "references": REFERENCES["csrf"],
                }
            )

    return findings

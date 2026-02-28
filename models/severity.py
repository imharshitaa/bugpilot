"""Severity levels for supported vulnerability categories."""

SEVERITY_LEVEL = {
    "xss": "medium",
    "sqli": "high",
    "ssrf": "high",
    "auth_bypass": "critical",
    "misconfig": "low",
    "idor": "high",
    "open_redirect": "medium",
    "path_traversal": "high",
    "file_inclusion_indicator": "high",
    "cors_misconfig": "medium",
    "csrf": "medium",
}


def get_severity(vuln_type: str) -> str:
    """Return the default severity for a vulnerability type."""
    return SEVERITY_LEVEL.get(vuln_type, "low")

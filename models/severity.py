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
    "rate_limit_bruteforce": "medium",
    "jwt_validation_weaknesses": "high",
    "insecure_deserialization": "high",
    "business_logic_abuse": "medium",
    "graphql_specific_testing": "medium",
    "file_upload_testing": "high",
    "xxe": "high",
}


def get_severity(vuln_type: str) -> str:
    """Return the default severity for a vulnerability type."""
    return SEVERITY_LEVEL.get(vuln_type, "low")

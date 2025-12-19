"""
severity.py
------------
Severity levels for different vulnerability types.
"""

SEVERITY_LEVEL = {
    "xss": "medium",
    "sqli": "high",
    "ssrf": "high",
    "auth_bypass": "critical",
    "misconfig": "low"
}

def get_severity(vuln_type: str) -> str:
    """
    Returns the severity string for a given vulnerability type.
    """
    return SEVERITY_LEVEL.get(vuln_type, "low")


"""
prompts.py
-----------
Contains templates for:
- Mitigation recommendations
- Exploitation method explanations (non-harmful)
- Reference documentation links
"""

MITIGATIONS = {
    "xss": "Sanitize user input, encode outputs, and enforce a strong CSP.",
    "sqli": "Use parameterized queries and avoid dynamic SQL string concatenation.",
    "ssrf": "Restrict internal traffic, validate URLs, enforce allowlists.",
    "auth_bypass": "Enforce authentication for all protected routes and use RBAC.",
    "misconfig": "Enable missing headers and follow OWASP secure configuration guidelines."
}

EXPLOIT_METHODS = {
    "xss": [
        "Trigger a JavaScript execution (harmless proof-of-concept).",
        "Reflect payload to observe input handling flaws."
    ],
    "sqli": [
        "Observe error signatures to infer database structure.",
        "Manipulate inputs to alter backend SQL behavior (safe detection only)."
    ],
    "ssrf": [
        "Check for internal IP access attempts.",
        "Probe metadata endpoints (safe observation only)."
    ],
    "auth_bypass": [
        "Access protected routes without credentials.",
        "Modify tokens or cookies to observe privilege issues."
    ],
    "misconfig": [
        "Use missing headers to simulate clickjacking.",
        "Analyze MIME-type weaknesses for unsafe file handling."
    ]
}

REFERENCES = {
    "xss": "https://owasp.org/www-community/attacks/xss/",
    "sqli": "https://owasp.org/www-community/attacks/SQL_Injection",
    "ssrf": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    "auth_bypass": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    "misconfig": "https://owasp.org/www-project-secure-headers/"
}


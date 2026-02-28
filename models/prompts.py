"""Mitigations, safe validation hints, and references per test category."""

MITIGATIONS = {
    "xss": "Sanitize user input, encode outputs, and enforce a strong CSP.",
    "sqli": "Use parameterized queries and avoid dynamic SQL string concatenation.",
    "ssrf": "Restrict internal traffic, validate URLs, enforce allowlists.",
    "auth_bypass": "Enforce authentication for all protected routes and use RBAC.",
    "misconfig": "Enable missing headers and follow OWASP secure configuration guidelines.",
    "idor": "Enforce object-level authorization checks on every resource access.",
    "open_redirect": "Allow only trusted relative paths or allowlisted destinations for redirects.",
    "path_traversal": "Normalize and validate file paths against strict allowlists.",
    "file_inclusion_indicator": "Disallow user-controlled include paths and harden file resolution logic.",
    "cors_misconfig": "Avoid wildcard origins and validate trusted origins explicitly.",
    "csrf": "Use anti-CSRF tokens and same-site cookie protections for state-changing actions.",
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
    ],
    "idor": [
        "Mutate object identifiers and compare authorization behavior between users.",
        "Validate object ownership checks for all resource lookups."
    ],
    "open_redirect": [
        "Supply external redirect targets and verify server-side validation.",
        "Test redirect parameters for open destination control."
    ],
    "path_traversal": [
        "Send encoded traversal payloads and inspect path handling errors.",
        "Confirm restricted filesystem paths cannot be accessed."
    ],
    "file_inclusion_indicator": [
        "Probe include parameters for stack traces and include() warnings.",
        "Verify include path handling is constrained to safe templates."
    ],
    "cors_misconfig": [
        "Test untrusted Origin headers and observe ACAO behavior.",
        "Verify credentialed cross-origin requests are not broadly allowed."
    ],
    "csrf": [
        "Inspect state-changing forms for anti-CSRF token enforcement.",
        "Validate SameSite and token-based anti-forgery controls."
    ],
}

REFERENCES = {
    "xss": "https://owasp.org/www-community/attacks/xss/",
    "sqli": "https://owasp.org/www-community/attacks/SQL_Injection",
    "ssrf": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    "auth_bypass": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    "misconfig": "https://owasp.org/www-project-secure-headers/",
    "idor": "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
    "open_redirect": "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
    "path_traversal": "https://owasp.org/www-community/attacks/Path_Traversal",
    "file_inclusion_indicator": "https://owasp.org/www-community/attacks/Path_Traversal",
    "cors_misconfig": "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    "csrf": "https://owasp.org/www-community/attacks/csrf",
}

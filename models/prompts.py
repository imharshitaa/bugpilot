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
    "rate_limit_bruteforce": "Apply per-account/IP throttling, lockouts, and adaptive rate controls.",
    "jwt_validation_weaknesses": "Enforce strong JWT signatures, algorithm pinning, and strict claim verification.",
    "insecure_deserialization": "Avoid unsafe object deserialization for untrusted input and use strict allowlists.",
    "business_logic_abuse": "Enforce server-side workflow and value integrity constraints on all transactions.",
    "graphql_specific_testing": "Disable introspection in production and enforce resolver-level authorization.",
    "file_upload_testing": "Validate MIME/content, enforce extension allowlists, and isolate uploaded files.",
    "xxe": "Disable external entities/DTDs in XML parsers and use hardened parser configuration.",
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
    "rate_limit_bruteforce": [
        "Send controlled burst traffic and observe throttling or lockout behavior.",
        "Verify repeated auth attempts trigger defensive controls."
    ],
    "jwt_validation_weaknesses": [
        "Inspect JWT headers/claims for weak algorithm acceptance.",
        "Verify token verification fails for tampered signatures."
    ],
    "insecure_deserialization": [
        "Replay serialization markers and inspect parser error responses.",
        "Verify untrusted serialized payloads are rejected safely."
    ],
    "business_logic_abuse": [
        "Tamper business parameters (price/quantity/order sequence) and inspect acceptance.",
        "Verify transaction workflow constraints are enforced server-side."
    ],
    "graphql_specific_testing": [
        "Probe GraphQL endpoint exposure and introspection behavior.",
        "Check resolver access controls for sensitive fields."
    ],
    "file_upload_testing": [
        "Inspect upload handlers for missing file type/extension constraints.",
        "Verify executable or malformed uploads are rejected."
    ],
    "xxe": [
        "Replay safe XXE parser probes and inspect parser error indicators.",
        "Validate XML parser is configured to reject external entities."
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
    "rate_limit_bruteforce": "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
    "jwt_validation_weaknesses": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Testing_JSON_Web_Tokens",
    "insecure_deserialization": "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
    "business_logic_abuse": "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
    "graphql_specific_testing": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    "file_upload_testing": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    "xxe": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
}

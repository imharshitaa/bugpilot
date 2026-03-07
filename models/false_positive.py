"""
false_positive.py
------------------
False positive patterns for filtering noisy results.
"""

FALSE_POSITIVE_PATTERNS = [
    "not found",
    "page not found",
    "bad request",
    "forbidden",
    "csrf token",
    "invalid token",
    "authorization required",
    "error 404"
]

def is_false_positive(text: str) -> bool:
    """
    Check if a scan evidence contains common false positive patterns.
    """
    text_lower = text.lower()
    return any(pattern in text_lower for pattern in FALSE_POSITIVE_PATTERNS)


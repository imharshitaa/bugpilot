"""
validator.py
-------------
Validates and cleans findings before reporting.
"""


class Validator:
    def trim_evidence(self, text):
        return text[:300] + "..." if len(text) > 300 else text

    def deduplicate(self, findings):
        unique = []
        seen = set()

        for finding in findings:
            key = (
                finding.get("type", "unknown"),
                finding.get("endpoint", "unknown"),
                finding.get("payload", "N/A"),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

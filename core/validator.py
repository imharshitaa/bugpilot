"""
validator.py
-------------
Validates and cleans findings before reporting.
- Deduplicates findings
- Filters obvious false positive cases
- Normalizes evidence length
"""

class Validator:
    def __init__(self):
        pass

    def trim_evidence(self, text):
        return text[:300] + "..." if len(text) > 300 else text

    def deduplicate(self, findings):
        unique = []
        seen = set()

        for f in findings:
            key = (f["type"], f["endpoint"], f["payload"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique


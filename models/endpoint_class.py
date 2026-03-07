"""
endpoint_class.py
------------------
Represents a single URL/endpoint with metadata.
Used by all modules for scanning & reporting.
"""

class Endpoint:
    def __init__(self, url, method="GET", params=None):
        self.url = url
        self.method = method
        self.params = params or {}

    def __repr__(self):
        return f"Endpoint(url={self.url}, method={self.method}, params={self.params})"

    def serialize(self):
        """
        Serialize endpoint for exporting into reports.
        """
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params
        }


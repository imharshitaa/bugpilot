"""
recon.py
---------
Performs lightweight reconnaissance:
- Detect server type
- Detect technologies via headers
- Check HTTPS enforcement
- Identify interesting server info
"""

class Recon:
    def __init__(self, utils):
        self.utils = utils

    def analyze_headers(self, url):
        resp = self.utils.http_request(url)
        if not resp:
            return {}

        info = {
            "server": resp.headers.get("Server", "Unknown"),
            "powered_by": resp.headers.get("X-Powered-By", "Unknown"),
            "security_headers": {
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security"),
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options"),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
                "X-Frame-Options": resp.headers.get("X-Frame-Options")
            }
        }

        return info










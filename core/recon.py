"""
recon.py
---------
Performs lightweight reconnaissance:
- Detect server type
- Detect technologies via headers
- Check HTTPS enforcement
- Identify interesting server info
"""

import socket
import ssl
from urllib.parse import urlsplit


class Recon:
    def __init__(self, utils):
        self.utils = utils

    def _resolve_dns(self, host):
        try:
            return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        except Exception:
            return []

    def _tls_summary(self, host, port=443):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            san = cert.get("subjectAltName", [])
            return {
                "subject_cn": subject.get("commonName"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san_count": len(san),
            }
        except Exception:
            return {}

    def analyze_headers(self, url):
        resp = self.utils.http_request(url)
        if not resp:
            return {}
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        info = {
            "target": url,
            "scheme": parsed.scheme,
            "host": host,
            "port": port,
            "resolved_ips": self._resolve_dns(host) if host else [],
            "server": resp.headers.get("Server", "Unknown"),
            "powered_by": resp.headers.get("X-Powered-By", "Unknown"),
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type"),
            "content_length": len(resp.text),
            "security_headers": {
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security"),
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options"),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
                "X-Frame-Options": resp.headers.get("X-Frame-Options"),
                "Referrer-Policy": resp.headers.get("Referrer-Policy"),
                "Permissions-Policy": resp.headers.get("Permissions-Policy"),
            },
        }
        if parsed.scheme == "https" and host:
            info["tls"] = self._tls_summary(host, port=port)

        return info









"""Isolated lab validation helpers for findings (safe replay checks only)."""

from urllib.parse import parse_qsl, urlsplit, urlunsplit

from bs4 import BeautifulSoup


class LabValidator:
    def __init__(self, utils, payload_rules):
        self.utils = utils
        self.payload_rules = payload_rules or {}

    def _param_for_type(self, vuln_type):
        mapping = {
            "xss": "test",
            "sqli": "id",
            "ssrf": "url",
            "open_redirect": "redirect",
            "path_traversal": "file",
            "file_inclusion_indicator": "file",
        }
        return mapping.get(vuln_type)

    def _extract_test_value(self, finding, vuln_type):
        payload = finding.get("payload", "N/A")
        if vuln_type == "idor":
            text = str(payload)
            marker = "to "
            if marker in text:
                return text.split(marker, 1)[1].strip()
        return None if payload in (None, "N/A") else str(payload)

    def _build_lab_url(self, finding, lab_environment, vuln_type):
        src = str(finding.get("endpoint", ""))
        if not src:
            return None

        parsed_src = urlsplit(src)
        if str(lab_environment).startswith("http://") or str(lab_environment).startswith("https://"):
            base = urlsplit(str(lab_environment))
            path = parsed_src.path
            query = parsed_src.query
            lab_url = urlunsplit((base.scheme, base.netloc, path, query, ""))
        else:
            lab_url = src

        param = self._param_for_type(vuln_type)
        value = self._extract_test_value(finding, vuln_type)
        if param and value:
            return self.utils.add_query_params(lab_url, {param: value})
        return lab_url

    def _contains_any(self, haystack, needles):
        text = str(haystack).lower()
        return any(str(n).lower() in text for n in needles)

    def _check_result(self, finding, vuln_type, response):
        if not response:
            return False, "No response received from isolated lab target."

        body = response.text
        payload = str(finding.get("payload", ""))
        rules = self.payload_rules

        if vuln_type == "xss":
            return payload and payload in body, "Payload reflection replay in lab response."
        if vuln_type == "sqli":
            sigs = rules.get("sqli", {}).get("error_signatures", [])
            return self._contains_any(body, sigs), "SQL error signature observed in lab response."
        if vuln_type == "ssrf":
            sigs = rules.get("ssrf", {}).get("match_indicators", [])
            return self._contains_any(body, sigs), "SSRF indicator observed in lab response."
        if vuln_type in ("path_traversal", "file_inclusion_indicator"):
            sigs = ["root:x:", "failed to open", "no such file", "warning: include"]
            return self._contains_any(body, sigs), "File/path handling indicator observed in lab response."
        if vuln_type == "open_redirect":
            return bool(response.history), "Redirect behavior replayed in lab."
        if vuln_type == "misconfig":
            required = rules.get("misconfig", {}).get("headers_to_check", [])
            missing = [h for h in required if h not in response.headers]
            return bool(missing), f"Missing security headers in lab: {', '.join(missing[:5])}"
        if vuln_type == "csrf":
            soup = BeautifulSoup(body, "html.parser")
            forms = soup.find_all("form")
            missing = 0
            for form in forms:
                if not form.find("input", {"name": "csrf_token"}):
                    missing += 1
            return missing > 0, f"Forms missing CSRF token in lab: {missing}"
        if vuln_type == "cors_misconfig":
            origin = response.headers.get("Access-Control-Allow-Origin")
            return origin in ("*", "https://evil.example"), f"Observed ACAO in lab: {origin}"
        if vuln_type in ("auth_bypass", "idor"):
            return response.status_code == 200, "Access pattern returned HTTP 200 in lab; manual auth comparison recommended."

        return False, "No replay checker defined for this finding type."

    def validate(self, finding, lab_environment):
        vuln_type = str(finding.get("normalized_type") or finding.get("type", "")).lower().replace(" ", "_")
        lab_url = self._build_lab_url(finding, lab_environment, vuln_type)
        if not lab_url:
            return {
                "status": "inconclusive",
                "vulnerability_type": vuln_type or "unknown",
                "source_target": finding.get("endpoint", "N/A"),
                "lab_target": None,
                "proof": "Missing source endpoint; unable to validate.",
            }

        headers = None
        if vuln_type == "cors_misconfig":
            headers = {"Origin": "https://evil.example"}

        response = self.utils.http_request(lab_url, extra_headers=headers)
        validated, proof = self._check_result(finding, vuln_type, response)

        status = "validated" if validated else "inconclusive"
        return {
            "status": status,
            "vulnerability_type": vuln_type or "unknown",
            "severity": str(finding.get("severity", "low")).lower(),
            "source_target": finding.get("endpoint", "N/A"),
            "lab_target": lab_url,
            "module": finding.get("module", "unknown"),
            "cwe": finding.get("cwe", "N/A"),
            "http_status": response.status_code if response else None,
            "proof": proof,
            "evidence_preview": (response.text[:180] if response else ""),
            "notes": "Safe replay only. Do exploitability confirmation exclusively in isolated lab assets you control.",
        }

"""Isolated lab validation helpers for findings (safe replay checks only)."""

import subprocess
from urllib.parse import urlsplit, urlunsplit

from bs4 import BeautifulSoup


class LabValidator:
    def __init__(self, utils, payload_rules, docker_auto_validation=False):
        self.utils = utils
        self.payload_rules = payload_rules or {}
        self.docker_auto_validation = docker_auto_validation

    def _param_for_type(self, vuln_type):
        mapping = {
            "xss": "test",
            "sqli": "id",
            "ssrf": "url",
            "open_redirect": "redirect",
            "path_traversal": "file",
            "file_inclusion_indicator": "file",
            "business_logic_abuse": "price",
            "insecure_deserialization": "data",
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
        if vuln_type == "rate_limit_bruteforce":
            return response.status_code != 429, "Single replay succeeded; validate burst-throttling behavior in lab traffic tests."
        if vuln_type == "jwt_validation_weaknesses":
            return "jwt" in body.lower() or "bearer" in body.lower(), "JWT handling behavior observed; verify signature enforcement with controlled token tests."
        if vuln_type == "insecure_deserialization":
            sigs = self.payload_rules.get("insecure_deserialization", {}).get("error_signatures", [])
            return self._contains_any(body, sigs), "Deserializer error signature observed in lab replay."
        if vuln_type == "business_logic_abuse":
            return response.status_code in (200, 201, 202), "Business tamper replay accepted in lab response."
        if vuln_type == "graphql_specific_testing":
            return "__schema" in body.lower() or "graphql" in body.lower(), "GraphQL introspection/exposure indicators observed."
        if vuln_type == "file_upload_testing":
            return "type=\"file\"" in body.lower(), "Upload form behavior still exposed in lab response."
        if vuln_type == "xxe":
            sigs = self.payload_rules.get("xxe", {}).get("error_signatures", [])
            return self._contains_any(body, sigs), "XML parser entity/error signature observed in lab replay."
        if vuln_type in ("auth_bypass", "idor"):
            return response.status_code == 200, "Access pattern returned HTTP 200 in lab; manual auth comparison recommended."

        return False, "No replay checker defined for this finding type."

    def _docker_request(self, url, headers=None):
        cmd = [
            "docker",
            "run",
            "--rm",
            "curlimages/curl:8.10.1",
            "-k",
            "-i",
            "-sS",
            url,
        ]
        for key, value in (headers or {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        try:
            completed = subprocess.run(
                cmd,
                check=False,
                text=True,
                capture_output=True,
                timeout=25,
            )
        except Exception:
            return None

        if completed.returncode != 0:
            return None

        raw = completed.stdout
        if "\r\n\r\n" in raw:
            header_part, body = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            header_part, body = raw.split("\n\n", 1)
        else:
            header_part, body = raw, ""

        status_code = None
        headers_map = {}
        for line in header_part.splitlines():
            lower = line.lower()
            if lower.startswith("http/"):
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    status_code = int(parts[1])
            elif ":" in line:
                key, value = line.split(":", 1)
                headers_map[key.strip()] = value.strip()

        class SimpleResponse:
            def __init__(self, status_code, headers, text):
                self.status_code = status_code
                self.headers = headers
                self.text = text
                self.history = []
                self.url = url

        return SimpleResponse(status_code, headers_map, body)

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

        response = None
        via = "native_http"
        if self.docker_auto_validation:
            response = self._docker_request(lab_url, headers=headers)
            via = "docker" if response is not None else "native_http_fallback"
        if response is None:
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
            "validation_transport": via,
            "notes": "Safe replay only. Do exploitability confirmation exclusively in isolated lab assets you control.",
        }

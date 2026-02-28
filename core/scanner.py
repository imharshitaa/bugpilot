"""Central scan engine: execute modules and enrich findings consistently."""

import importlib
from urllib.parse import urlsplit

import yaml

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


RISK_SUMMARY = {
    "critical": "Immediate exploitation risk with likely high business impact.",
    "high": "High likelihood of compromise or data exposure.",
    "medium": "Moderate exploitability; can be chained for larger impact.",
    "low": "Low direct impact but can weaken overall security posture.",
}

LAB_VALIDATION_GUIDE = {
    "xss": "Reproduce on a local vulnerable app page and confirm harmless script execution.",
    "sqli": "Replay against an intentional test environment and verify database error behavior only.",
    "ssrf": "Use a lab callback service to confirm server-side fetch behavior in a controlled setup.",
    "auth_bypass": "Use a test account matrix in staging and validate broken access controls.",
    "misconfig": "Verify missing security header behavior using browser/security scanners in staging.",
    "idor": "Use two authorized test users in staging and validate object ownership checks.",
    "open_redirect": "Validate untrusted redirect behavior against an allowlist policy in staging.",
    "path_traversal": "Verify blocked traversal payloads in a sandbox app with synthetic files.",
    "file_inclusion_indicator": "Use a local vulnerable app and confirm inclusion defenses in place.",
    "cors_misconfig": "Re-test cross-origin requests in staging with a strict allowed origin list.",
    "csrf": "Simulate cross-site form submission in staging and confirm CSRF token validation.",
}


class Scanner:
    def __init__(self, utils, validator):
        self.utils = utils
        self.validator = validator
        self.module_config = self._load_yaml("config/modules.yaml")
        self.payload_rules = self._load_yaml("config/payload_rules.yaml")
        scanner_cfg = self.utils.settings.get("scanner", {})
        self.max_endpoints_per_module = scanner_cfg.get("max_endpoints_per_module", 15)
        self.skip_static_extensions = tuple(
            ext.lower() for ext in scanner_cfg.get("skip_static_extensions", [])
        )
        self._snapshot_cache = {}

    def _load_yaml(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def available_modules(self):
        return self.module_config.get("modules", {})

    def run_modules(self, endpoints, selected_modules=None):
        findings = []
        modules = self.available_modules()

        if selected_modules is None:
            selected_modules = [
                name for name, meta in modules.items() if meta.get("enabled", False)
            ]

        for module_name in selected_modules:
            module_meta = modules.get(module_name, {})
            if not module_meta.get("enabled", False):
                continue

            try:
                module = importlib.import_module(f"modules.{module_name}")
                module_endpoints = self._prepare_endpoints(endpoints)
                module_findings = module.run(module_endpoints, self.utils, self.payload_rules)
            except Exception as exc:
                self.utils.log(f"Module {module_name} failed: {exc}")
                continue

            for finding in module_findings:
                findings.append(self._enrich_finding(finding, module_name))

        return self.validator.deduplicate(findings)

    def _prepare_endpoints(self, endpoints):
        filtered = []
        for endpoint in endpoints:
            path = urlsplit(endpoint.url).path.lower()
            if self.skip_static_extensions and path.endswith(self.skip_static_extensions):
                continue
            filtered.append(endpoint)

        if self.max_endpoints_per_module and self.max_endpoints_per_module > 0:
            return filtered[: self.max_endpoints_per_module]
        return filtered

    def _normalize_type(self, finding):
        raw = str(finding.get("type", "unknown")).strip().lower()
        slug = raw.replace(" ", "_").replace("-", "_")
        if slug == "server_side_request_forgery":
            return "ssrf"
        if slug == "cross_site_request_forgery":
            return "csrf"
        if slug == "file_inclusion":
            return "file_inclusion_indicator"
        return slug

    def _response_snapshot(self, url):
        if url in self._snapshot_cache:
            return self._snapshot_cache[url]

        resp = self.utils.http_request(url)
        if not resp:
            snapshot = {
                "status_code": None,
                "content_type": None,
                "server": None,
                "notes": "No response captured",
            }
            self._snapshot_cache[url] = snapshot
            return snapshot

        snapshot = {
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type"),
            "server": resp.headers.get("Server"),
            "content_length": len(resp.text),
            "interesting_headers": {
                "X-Frame-Options": resp.headers.get("X-Frame-Options"),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
                "Access-Control-Allow-Origin": resp.headers.get(
                    "Access-Control-Allow-Origin"
                ),
            },
        }
        self._snapshot_cache[url] = snapshot
        return snapshot

    def _enrich_finding(self, finding, module_name):
        vuln_type = self._normalize_type(finding)
        severity = str(finding.get("severity") or get_severity(vuln_type)).lower()

        if vuln_type in MITIGATIONS:
            finding["mitigation"] = finding.get("mitigation") or MITIGATIONS[vuln_type]
        if vuln_type in REFERENCES:
            finding["references"] = finding.get("references") or REFERENCES[vuln_type]
        if vuln_type in EXPLOIT_METHODS:
            finding["exploitation_methods"] = finding.get("exploitation_methods") or (
                "\n- " + "\n- ".join(EXPLOIT_METHODS[vuln_type])
            )

        finding["normalized_type"] = vuln_type
        finding["module"] = module_name
        finding["severity"] = severity
        finding["risk"] = RISK_SUMMARY.get(severity, RISK_SUMMARY["low"])
        finding["vulnerability_point"] = finding.get("endpoint", "unknown")
        finding["target_response"] = self._response_snapshot(
            finding.get("endpoint", "")
        )
        finding["lab_validation"] = LAB_VALIDATION_GUIDE.get(
            vuln_type,
            "Validate in an isolated staging/lab environment before reporting.",
        )

        return finding

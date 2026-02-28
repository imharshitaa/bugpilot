"""Central scan engine: execute plugins and enrich findings consistently."""

import copy
from urllib.parse import urlsplit

import yaml

from core.plugin_manager import PluginManager
from core.risk_scorer import RiskScorer
from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


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
    "rate_limit_bruteforce": "Replay bursts in rate-limited staging and verify lockout or throttling.",
    "jwt_validation_weaknesses": "Verify token signature/claims validation in a controlled auth lab.",
    "insecure_deserialization": "Replay payload markers in a local vulnerable parser sandbox.",
    "business_logic_abuse": "Validate workflow guards and price/quantity controls in staging.",
    "graphql_specific_testing": "Validate GraphQL introspection and resolver auth constraints in staging.",
    "file_upload_testing": "Use a lab upload endpoint and verify strict content validation.",
    "xxe": "Replay XML entity probes in a lab parser with external entity access disabled.",
}


class Scanner:
    def __init__(self, utils, validator):
        self.utils = utils
        self.validator = validator
        self.plugin_manager = PluginManager()
        self.payload_rules = self._load_yaml("config/payload_rules.yaml")
        self.risk_scorer = RiskScorer()
        scanner_cfg = self.utils.settings.get("scanner", {})
        self.max_endpoints_per_module = scanner_cfg.get("max_endpoints_per_module", 15)
        self.fast_mode = bool(scanner_cfg.get("fast_mode", True))
        self.max_payloads_per_test = int(scanner_cfg.get("max_payloads_per_test", 2))
        self.skip_static_extensions = tuple(
            ext.lower() for ext in scanner_cfg.get("skip_static_extensions", [])
        )
        self._snapshot_cache = {}
        self.runtime_payload_rules = self._build_runtime_payload_rules()

    def _load_yaml(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def available_modules(self):
        plugins = self.plugin_manager.list_plugins()
        return {
            name: {
                "enabled": meta.get("enabled", False),
                "description": meta.get("description", ""),
            }
            for name, meta in plugins.items()
        }

    def run_modules(self, endpoints, selected_modules=None, progress_callback=None):
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
                if progress_callback:
                    progress_callback(
                        "start",
                        {
                            "module": module_name,
                            "endpoints": len(endpoints),
                            "fast_mode": self.fast_mode,
                        },
                    )
                self.utils.set_active_module(module_name)
                module = self.plugin_manager.load_plugin(module_name)
                module_endpoints = self._prepare_endpoints(endpoints)
                module_findings = module.run(module_endpoints, self.utils, self.runtime_payload_rules)
            except Exception as exc:
                self.utils.log(f"Module {module_name} failed: {exc}")
                if progress_callback:
                    progress_callback("error", {"module": module_name, "error": str(exc)})
                continue
            finally:
                if self.utils.active_module == module_name:
                    self.utils.set_active_module(None)

            for finding in module_findings:
                findings.append(self._enrich_finding(finding, module_name))

            if progress_callback:
                progress_callback(
                    "done",
                    {
                        "module": module_name,
                        "findings": len(module_findings),
                        "stats": self.utils.get_module_stats(module_name),
                        "tested_endpoints": len(module_endpoints),
                    },
                )

        return self.validator.deduplicate(findings)

    def _build_runtime_payload_rules(self):
        if not self.fast_mode:
            return self.payload_rules

        rules = copy.deepcopy(self.payload_rules)
        shrinkable_list_keys = {"payloads", "payload_markers", "error_signatures", "match_indicators"}
        for _, value in rules.items():
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in shrinkable_list_keys and isinstance(item, list):
                        value[key] = item[: self.max_payloads_per_test]
                    if key == "tamper_params" and isinstance(item, dict):
                        entries = list(item.items())[: self.max_payloads_per_test]
                        value[key] = dict(entries)
        return rules

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
        if slug == "graphql":
            return "graphql_specific_testing"
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
        finding.update(self.risk_scorer.score(finding))
        finding["vulnerability_point"] = finding.get("endpoint", "unknown")
        finding["target_response"] = self._response_snapshot(
            finding.get("endpoint", "")
        )
        finding["lab_validation"] = LAB_VALIDATION_GUIDE.get(
            vuln_type,
            "Validate in an isolated staging/lab environment before reporting.",
        )

        return finding

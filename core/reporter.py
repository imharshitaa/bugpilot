"""Writes structured outputs (JSON/Markdown/SARIF) under reports/output."""

import datetime
import json
import os


class Reporter:
    def __init__(self, output_base="reports/output"):
        self.output_base = output_base

    def _run_dir(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        run_id = f"run_{timestamp}"
        path = os.path.join(self.output_base, run_id)
        os.makedirs(path, exist_ok=True)
        return run_id, path

    def _severity_counts(self, findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            sev = str(finding.get("severity", "low")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _build_markdown(self, run_context, endpoints, findings):
        counts = self._severity_counts(findings)
        now = datetime.datetime.now().isoformat()

        lines = [
            "# BugPilot Findings Report",
            "",
            "## Scan Context",
            f"- Scan Date: {now}",
            f"- Target Type: {run_context.get('target_type')}",
            f"- Targets: {', '.join(run_context.get('targets', []))}",
            f"- Exploitation Policy: {run_context.get('exploitation_policy')}",
            f"- Lab Validation Environment: {run_context.get('lab_environment')}",
            f"- Endpoints Discovered: {len(endpoints)}",
            f"- Findings: {len(findings)}",
            "",
            "## Severity Summary",
            f"- Critical: {counts['critical']}",
            f"- High: {counts['high']}",
            f"- Medium: {counts['medium']}",
            f"- Low: {counts['low']}",
            "",
            "## Selected Test Cases",
        ]

        for module, plan in run_context.get("test_plan", {}).items():
            lines.extend(
                [
                    f"### {module}",
                    f"- Attack Method: {plan.get('attack_method')}",
                    f"- Custom Scripts: {', '.join(plan.get('custom_scripts', []))}",
                    f"- Kali Tools: {', '.join(plan.get('tools', {}).get('kali', []))}",
                    f"- Open Source Tools: {', '.join(plan.get('tools', {}).get('opensource', []))}",
                    f"- Commands: {', '.join(plan.get('commands', []))}",
                    "",
                ]
            )

        lines.append("## Detailed Findings")
        lines.append("")

        if not findings:
            lines.append("No findings detected in this run.")
            lines.append("")

        for idx, finding in enumerate(findings, start=1):
            target_response = finding.get("target_response", {})
            lines.extend(
                [
                    f"### {idx}. {finding.get('type', 'unknown').upper()} ({finding.get('severity', 'low').upper()})",
                    f"- Module/Test Case: {finding.get('module', 'unknown')}",
                    f"- CWE: {finding.get('cwe', 'N/A')}",
                    f"- Vulnerability Point: {finding.get('vulnerability_point', 'N/A')}",
                    f"- Endpoint: {finding.get('endpoint', 'N/A')}",
                    f"- Payload/Test Input: {finding.get('payload', 'N/A')}",
                    f"- Evidence: {finding.get('evidence', 'N/A')}",
                    f"- Risk: {finding.get('risk', 'N/A')}",
                    f"- Risk Score: {finding.get('risk_score', 'N/A')}",
                    f"- Risk Rating: {finding.get('risk_rating', 'N/A')}",
                    f"- Mitigation: {finding.get('mitigation', 'N/A')}",
                    f"- References: {finding.get('references', 'N/A')}",
                    f"- Lab Validation (controlled environment): {finding.get('lab_validation', 'N/A')}",
                    "- Target Response Snapshot:",
                    f"  - status_code: {target_response.get('status_code')}",
                    f"  - content_type: {target_response.get('content_type')}",
                    f"  - server: {target_response.get('server')}",
                    f"  - content_length: {target_response.get('content_length')}",
                    "",
                ]
            )

        return "\n".join(lines)

    def _build_sarif(self, findings):
        rules = {}
        results = []

        for finding in findings:
            rule_id = str(finding.get("normalized_type") or finding.get("type", "unknown"))
            level = str(finding.get("severity", "low")).lower()
            if level not in ("error", "warning", "note"):
                level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(level, "note")

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": str(finding.get("type", rule_id))},
                    "help": {"text": str(finding.get("mitigation", "Review and remediate finding."))},
                    "properties": {"tags": ["security"]},
                }

            endpoint = str(finding.get("endpoint", ""))
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": str(finding.get("evidence", "Potential vulnerability detected."))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": endpoint or "unknown_target"}
                            }
                        }
                    ],
                }
            )

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BugPilot",
                            "informationUri": "https://github.com/imharshitaa/bugpilot",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def write(self, run_context, endpoints, findings, utils):
        run_id, run_path = self._run_dir()
        output_formats = run_context.get("output_formats", ["markdown", "json"])
        output_formats = [fmt.strip().lower() for fmt in output_formats]

        md_path = os.path.join(run_path, "report.md")
        json_path = os.path.join(run_path, "findings.json")
        context_path = os.path.join(run_path, "context.json")
        endpoints_path = os.path.join(run_path, "endpoints.json")
        sarif_path = os.path.join(run_path, "results.sarif")
        session_path = os.path.join(run_path, "session.json")

        if "markdown" in output_formats:
            markdown = self._build_markdown(run_context, endpoints, findings)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(markdown)

        if "json" in output_formats or "sarif" in output_formats:
            utils.write_json(json_path, findings)
        utils.write_json(context_path, run_context)
        utils.write_json(endpoints_path, [endpoint.serialize() for endpoint in endpoints])
        utils.write_json(
            session_path,
            {
                "target_type": run_context.get("target_type"),
                "targets": run_context.get("targets", []),
                "selected_modules": run_context.get("selected_modules", []),
                "lab_environment": run_context.get("lab_environment"),
                "output_formats": output_formats,
                "test_plan": run_context.get("test_plan", {}),
                "replay_source_run_id": run_context.get("replay_source_run_id"),
            },
        )

        if "sarif" in output_formats:
            sarif = self._build_sarif(findings)
            with open(sarif_path, "w", encoding="utf-8") as f:
                json.dump(sarif, f, indent=2)

        outputs = {
            "run_id": run_id,
            "run_path": run_path,
            "context_json": context_path,
            "endpoints_json": endpoints_path,
            "session_json": session_path,
        }
        if "markdown" in output_formats:
            outputs["markdown"] = md_path
        if "json" in output_formats or "sarif" in output_formats:
            outputs["findings_json"] = json_path
        if "sarif" in output_formats:
            outputs["sarif"] = sarif_path

        return outputs
